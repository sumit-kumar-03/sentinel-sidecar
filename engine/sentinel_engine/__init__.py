"""sentinel-sidecar inline engine: an HTTP ext_authz service.

Envoy calls this service for every inspected request. The engine extracts
features, runs the scorer ensemble, maps the combined risk to an action under
the active mode, tells Envoy to allow or block, and emits an event to Redis
out of band. Phase 2 ships the framework with a single heuristic stand-in for
the M1 model; Phases 3-4 replace and add the real ONNX scorers.
"""

__version__ = "0.2.0"
