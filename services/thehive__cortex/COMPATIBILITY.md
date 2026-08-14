# Cortex 3.1 compatibility evidence

The adapter's request paths and response mapping are verified by the local
mock suite in `test/cortex.test.js`. It covers the Cortex 3.1 REST endpoints
used by this package, authentication, status/report variants, and error
handling.

An official-container check was attempted on 2026-08-14:

```sh
docker pull thehiveproject/cortex:3.1.7
docker run --rm thehiveproject/cortex:3.1.7 --help
```

The pull completed with digest
`sha256:f4bc64fb8844f4624274395e42b2f37db600bcd81d6b3edbf64695e7dccb8ae9`.
The container could not be started because the official image is `linux/amd64`
while the available runner is `linux/arm64/v8`; Docker reported
`exec /opt/cortex/entrypoint: exec format error`. Therefore this repository
contains mock-only compatibility evidence, not a claim of a live Cortex API
verification. Re-run the two commands above on an amd64 Docker host before
releasing against a real Cortex deployment.
