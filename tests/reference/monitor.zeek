# Run with -b. Keep existing interactive-port timeouts, but do not load
# Conn::Info / conn.log: they duplicate state we can read from connection.
@load base/protocols/conn/inactivity

# Required for endpoint$num_bytes_ip; do not substitute payload byte counts.
redef use_conn_size_analyzer = T;

module Monitor;

export {
    type PortRange: record {
        first: count;
        last: count;
    };
    # 0.0.0.0 and [::] are family-specific LOCAL wildcard keys, not literal hosts.
    const local_hosts: set[addr] = set() &redef;
    const rules: table[addr, transport_proto] of vector of PortRange = table() &redef;
}

# Do not create default business/diagnostic logs.
redef Log::enable_local_logging = F;
redef Log::enable_remote_logging = F;

function matches_rule(host: addr, endpoint: port, proto: transport_proto): bool
    {
    if ( [host, proto] !in rules )
        return F;
    local n = port_to_count(endpoint);
    for ( i, bounds in rules[host, proto] )
        if ( n >= bounds$first && n <= bounds$last )
            return T;
    return F;
    }

function is_server(host: addr, endpoint: port, proto: transport_proto): bool
    {
    # Exact and wildcard rules are additive; an exact rule for another port
    # must not suppress a matching wildcard. Never change the recorded address.
    local wildcard: addr = is_v4_addr(host) ? 0.0.0.0 : [::];
    local is_local = host in local_hosts || host in 127.0.0.0/8 || host == [::1];
    return matches_rule(host, endpoint, proto) ||
           (is_local && matches_rule(wildcard, endpoint, proto));
    }

type Session: record {
    kind: string;
    remote_addr: addr;
    remote_port: count;
    server_addr: addr;
    server_port: count;
    protocol: string;
    bytes_sent: count;
    bytes_received: count;
    session_time: double;
};

global output: file;

event zeek_init() &priority=-1000
    {
    output = open("/dev/stdout");
    set_buf(output, F);
    print output, "{\"kind\":\"ready\"}";
    }

# Same lifecycle as the former Conn::log_conn path, without a second record
# attached to every connection (including connections we never log).
event connection_state_remove(c: connection)
    {
    local proto = get_port_transport_proto(c$id$resp_p);
    if ( proto != tcp && proto != udp )
        return;
    local orig_server = is_server(c$id$orig_h, c$id$orig_p, proto);
    local resp_server = is_server(c$id$resp_h, c$id$resp_p, proto);
    if ( orig_server == resp_server )
        return;
    local s: Session = [
        $kind="session",
        $remote_addr=orig_server ? c$id$resp_h : c$id$orig_h,
        $remote_port=port_to_count(orig_server ? c$id$resp_p : c$id$orig_p),
        $server_addr=orig_server ? c$id$orig_h : c$id$resp_h,
        $server_port=port_to_count(orig_server ? c$id$orig_p : c$id$resp_p),
        $protocol=proto == tcp ? "TCP" : "UDP",
        $bytes_sent=orig_server ? c$orig$num_bytes_ip : c$resp$num_bytes_ip,
        $bytes_received=orig_server ? c$resp$num_bytes_ip : c$orig$num_bytes_ip,
        $session_time=interval_to_double(c$duration)
    ];
    print output, to_json(s);
    }

# Report capture-system drops on graceful shutdown, on stderr only. A zero
# value does not establish end-to-end capture completeness.
event net_done(t: time)
    {
    if ( reading_live_traffic() )
        {
        local stats = get_net_stats();
        Reporter::info(fmt("[zeek-monitor] capture: received=%d dropped=%d (capture-system counters)",
                           stats$pkts_recvd, stats$pkts_dropped));
        }
    }
