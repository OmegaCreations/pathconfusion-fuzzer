FROM envoyproxy/envoy:v1.31-latest
COPY envoy.yaml /etc/envoy/envoy.yaml
EXPOSE 8381
CMD ["envoy", "-c", "/etc/envoy/envoy.yaml"]
