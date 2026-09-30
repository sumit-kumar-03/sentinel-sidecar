# The gateway is Envoy with the Coraza WASM plugin (OWASP CRS 4.14.0) baked in,
# so the image is self-contained. The rendered envoy.yaml is provided at runtime
# by the sentinel-config container through a shared volume.
FROM envoyproxy/envoy:v1.37.6@sha256:ea33a83e4bb1b34b9345f1d98930af9c70d19a0ee1680d9ff087789636fdbc34
COPY wasm/coraza.wasm /wasm/coraza.wasm
