"""sentinel-sidecar out-of-band analyst.

Consumes the engine's event stream and, off the request path, (1) correlates
events over time to detect campaigns (distributed credential stuffing, slow
scans) and (2) sends gray-zone events to an LLM (M5, via Ollama) for a
schema-validated verdict. It only produces findings; applying them (TTL blocks,
threshold nudges) is the Phase 6 feedback loop.
"""

__version__ = "0.5.0"
