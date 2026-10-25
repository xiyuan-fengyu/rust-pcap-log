IMAGE ?= rust-pcap-log:test
BUILD_IMAGE ?= rust-pcap-log:build-test
ZEEK_IMAGE ?= zeek-monitor:memory-optimized
DOCKER_BUILD_FLAGS ?=
TEST_ENV = RUST_TEST_IMAGE=$(IMAGE) RUST_BUILD_IMAGE=$(BUILD_IMAGE) ZEEK_TEST_IMAGE=$(ZEEK_IMAGE)

.PHONY: build unit test reference benchmark
build:
	docker build $(DOCKER_BUILD_FLAGS) -t $(IMAGE) .
unit:
	docker build $(DOCKER_BUILD_FLAGS) --target test -t $(BUILD_IMAGE) .
reference:
	docker build -t rust-pcap-log:zeek-reference tests/reference/legacy
test: unit build
	$(TEST_ENV) python3 tests/differential.py
	$(TEST_ENV) python3 tests/tcp_cycles.py
	$(TEST_ENV) python3 -m unittest discover -s tests -p 'test_*.py' -v
benchmark:
	python3 tests/benchmark.py --image $(ZEEK_IMAGE) --image $(IMAGE) --repeats 3 --output .artifacts/memory/baseline.json
	python3 tests/benchmark.py --image $(ZEEK_IMAGE) --image $(IMAGE) --repeats 3 --extended --output .artifacts/memory/extended.json
	python3 tests/summarize_benchmark.py .artifacts/memory/baseline.json .artifacts/memory/extended.json
