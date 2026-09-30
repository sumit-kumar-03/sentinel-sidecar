DEMO := docker compose -f deploy/compose/demo/compose.yaml
CONTROL_IMAGE ?= sentinel-sidecar/control:dev
GATEWAY_IMAGE ?= sentinel-sidecar/gateway:dev
ENGINE_IMAGE ?= sentinel-sidecar/engine:dev
ANALYST_IMAGE ?= sentinel-sidecar/analyst:dev
CONFIG ?= sentinel.example.yaml

.PHONY: test validate validate-live gate wasm images demo-up demo-down demo-logs smoke

test:
	cd control && python3 -m unittest discover -s tests -t . -v
	cd engine && python3 -m unittest discover -s tests -t . -v
	cd analyst && python3 -m unittest discover -s tests -t . -v

validate:
	cd control && python3 -m sentinel_control validate ../$(CONFIG)

wasm:
	test -f gateway/wasm/coraza.wasm || gateway/wasm/fetch.sh

images: wasm
	docker build -t $(CONTROL_IMAGE) control
	docker build -t $(GATEWAY_IMAGE) gateway
	docker build -t $(ENGINE_IMAGE) engine
	docker build -t $(ANALYST_IMAGE) analyst

demo-up: images
	$(DEMO) up -d --wait

demo-down:
	$(DEMO) down -v

demo-logs:
	$(DEMO) logs -f sentinel-gateway

smoke:
	scripts/smoke.sh

TRAINING_IMAGE ?= sentinel-sidecar/training:dev

train:
	docker build -t $(TRAINING_IMAGE) training
	docker run --rm -v $(PWD)/engine/models:/work/out $(TRAINING_IMAGE)

replay:
	docker run --rm -v $(PWD)/eval/replay.py:/app/eval_replay.py:ro --entrypoint python $(ENGINE_IMAGE) /app/eval_replay.py

# Point at a running enforce-mode sidecar (default the demo port).
VALIDATE_URL ?= http://127.0.0.1:8090

validate-live: replay
	python3 eval/gate/run.py $(VALIDATE_URL)
	python3 eval/gate/latency.py $(VALIDATE_URL) 500

gate:
	eval/gate/run_gate.sh
