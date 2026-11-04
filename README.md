# trace_dns

Trace DNS requests and responses with [Inspektor Gadget](https://inspektor-gadget.io/).
The gadget captures UDP and TCP packets on ports 53 and 5353 over IPv4 and IPv6.
Each `dns` event includes a timestamp, source and destination endpoints, nameserver,
packet direction, and process information when the socket can be identified.

## Requirements

- Linux 5.10 or later with BTF (`/sys/kernel/btf/vmlinux`) and BPF socket-filter support.
- IG v0.57.0 and Docker for the default containerized build.
- Root privileges to build/run with the supplied Makefile.

The default builder image is pinned to IG v0.57.0.

## Build and run

```bash
# In one terminal:
PARAMS="--host" make run-local
# In another terminal (requires dig):
dig @1.1.1.1 example.com
```

Expect `dns` records for the query and response, with endpoint information and
the `dig` process when socket attribution is available.
Stop tracing with Ctrl-C. `make run-local` builds the current sources, then runs
the unsigned local image without pulling from a registry. Pass runtime options
through `PARAMS`. To run an already-built image, use `make run` instead:

```bash
make build IMAGE_TAG=latest
PARAMS="--verify-image=false --host" make run IMAGE_TAG=latest
sudo ig run ghcr.io/mqasimsarfraz/trace_dns:latest --verify-image=false --host -o json
make push IMAGE_TAG=latest
```

`--verify-image=false` permits unsigned images; sign images before distributing
them for production use.
Push requires registry authentication and permission to publish to `ghcr.io/mqasimsarfraz/trace_dns`.

## Automatic publishing

The initialization workflow and validated default-branch pushes publish
`ghcr.io/mqasimsarfraz/trace_dns:latest` and `ghcr.io/mqasimsarfraz/trace_dns:sha-<full-commit-SHA>` using `GITHUB_TOKEN` with
`packages: write`. Pull requests and other branches never publish. A repeated
initialization run does not republish.

Repository/organization policies must allow package writes. For an existing
package, grant this repository Actions access in the GHCR package settings.
New packages are private by default; change their visibility to allow public
pulls. To enable signing, configure the optional `COSIGN_PRIVATE_KEY` and
`COSIGN_PASSWORD` Actions secrets. Without a key, CI warns and publishes unsigned
images. See [Signing and verifying gadgets](SIGNING.md) for setup and public-key
configuration for `ig`, `kubectl gadget deploy`, and Helm.

## Events and limitations

The BPF program emits packet metadata and appends the captured packet for
userspace decoding. `gadget.yaml` also describes decoded fields such as `name`,
`qtype`, `qr`, `rcode`, and `addresses`, but this repository currently has no
userspace DNS parser implementation. Metadata alone does not populate those
fields.

`latency_ns` measures the time between an outgoing query and an incoming response
matched by process/thread ID and DNS transaction ID. It requires socket
attribution and a stored query timestamp; an unmatched response has a raw latency
of zero. The query map holds up to 1,024 entries. Unanswered queries remain in
the map because this repository does not implement the userspace garbage
collection mentioned in the BPF source; a full map prevents tracking new queries.

TCP parsing is best effort: the gadget does not reassemble TCP segments.
Encrypted DNS payloads (such as DNS over TLS or HTTPS) are not decoded.

Use `--paths` to collect the process working directory (`cwd`) and executable
path (`exepath`) when available from socket metadata. These columns are hidden
by default; use JSON output to inspect them:

```bash
PARAMS="--host --paths -o json" make run-local
```

## Customize

`program.bpf.c` defines `GADGET_TRACER(dns, events, event_t)` and attaches a socket
filter. Change `ports` and `ports_len` together to capture other DNS ports
(up to 16); these are compile-time settings, not exposed runtime parameters.
Reuse `gadget_process_populate_from_socket()` and
`gadget_should_discard_data_by_skb()` for socket-based process information and
filtering. `--pid`, `--comm`, and IG's container filters restrict collected events;
network namespace and socket information enable container/Kubernetes enrichment
when IG has the corresponding runtime metadata. `--host` includes host processes;
without it, IG collects from containers by default.

Events are emitted through a perf event array; buffer exhaustion can cause lost
samples.
Run `make metadata IMAGE_TAG=latest` after changing the event structure, review
`gadget.yaml`, then `make check` to check formatting (`make clang-format` fixes it).
Ordinary `make build` validates metadata without rewriting it.

The retained initialization workflow safely does nothing on subsequent runs.

## License

Userspace tooling is [Apache-2.0](LICENSE). The BPF program is
[GPL-2.0 WITH Linux-syscall-note](LICENSE-bpf.txt).
