This is a simple Go tool to check if the OCP API server supports ML-KEM.

# Prerequisite:
Use Go version 1.25+ since it requires ML-KEM support in Go & support for `tls.ConnectionState.CurveID` support. Tested with go version go1.25.0 (from upstream) on RHEL 10
If running with a self-signed certificate, you'll need to extract it:
echo Q | openssl s_client -connect api.<cluster>:6443 -CAfile ./ca.crt

# Build:
go build -trimpath -ldflags="-s -w" -o ocp-mlkem-check ./main.go

# Usage of ocp-mlkem-check:
```
  -ca-file string
    	Custom CA bundle (PEM). Defaults to in-cluster CA if running in cluster; else system roots.
  -classical-only
    	Do not offer PQ groups (use classical only)
  -force-mlkem
    	Prefer X25519MLKEM768 for key exchange
  -insecure-skip-verify
    	Skip TLS verification (NOT recommended)
  -path string
    	HTTP path to GET (only for completing TLS handshake; can be unauthorized) (default "/version")
  -require-mlkem
    	Exit non-zero unless the negotiated CurveID is X25519MLKEM768
  -server string
    	API server URL (default: in-cluster https://kubernetes.default.svc:443)
  -timeout duration
    	Overall HTTP client timeout (default 5s)
```
# Use within OpenShift
1- Use the Dockerfile

2- Build and push:
```
export IMG=quay.io/<org>/ocp-mlkem-check:latest   # or ghcr.io/<you>/..., or your internal registry
docker build -t "$IMG" .
docker push "$IMG"
```

3- Adjust `ocp-test-job.yaml` to pull from your repository

4- Create a project for the test, apply the yaml, check the logs:
```
oc new-project mlkem-test
oc apply -f job.yaml
oc logs -n mlkem-test job/ocp-mlkem-check
oc get jobs -n mlkem-test
```
