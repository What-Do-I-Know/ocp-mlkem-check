# ---- Build stage (Go 1.25) ----
FROM golang:1.25 AS build
WORKDIR /src
COPY . .
# Produce a static binary (no libc) for tiny, secure runtime images
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ocp-mlkem-check ./main.go

# ---- Runtime stage (distroless, nonroot) ----
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/ocp-mlkem-check /ocp-mlkem-check
USER 65532:65532
ENTRYPOINT ["/ocp-mlkem-check"]
