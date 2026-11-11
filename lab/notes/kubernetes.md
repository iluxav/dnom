# Kubernetes lab run (k3s, 2026-11-09)

Does pod and namespace context reach dnom's episodes and policies on a real cluster?
Reproduce with `make vm-start && make vm-k3s` (20 checks; results in
`~/.local/state/dnom/vm-k3s/`).

- **Cluster:** k3s v1.37.2+k3s1, one node in the lab VM (`lab/vm`), containerd 2.3.7,
  kernel 7.0.0-42. Traefik, ServiceLB, CoreDNS, metrics-server and local storage disabled.
- **Sensor:** Falco 0.45.2 as a DaemonSet (`lab/vm/k3s/falco.yaml`): modern eBPF, only
  the dnom catch-all rules, the k3s containerd socket mounted for pod metadata.
- **Pods** (`lab/vm/k3s/workload.yaml`): `web` in `dnom-test` and the same `web` in
  `dnom-other` (each reads its own `/etc/shadow` and tries TEST-NET-3), and `db` in
  `dnom-test`, which the test `kubectl exec`s into.
- **dnom:** classifies Falco's alerts on the host, with a test rule
  `k8s.namespace == "dnom-test" and files.credentials > 0` added to a copy of `dnom.yaml`.

## What works

| Check | Result |
|---|---|
| Falco alerts carry `k8s.pod.name` / `k8s.ns.name` | yes, for all three test pods |
| Each pod is its own episode, labelled with name, image, pod, namespace | yes |
| `kubectl exec` into a running pod | its own episode, labelled with the pod |
| Namespace-scoped rule | matches in `dnom-test`, not the same activity in `dnom-other` |
| Host episodes | no container block; the scoped rule never matches them |
| Jev | web pod: credential_access 0.97, exfiltration 0.10, response `alert`, 135 ms |

## Findings

| # | Finding | Status |
|---|---|---|
| 1 | containerd reports images in full (`docker.io/library/alpine`), Docker in short form (`alpine`) | fixed: dnom uses Docker's short form, so one policy matches both |
| 2 | Falco looks container metadata up asynchronously; a pod's first events can carry only its id | fixed: later events fill in the episode's labels (unit test; not seen in these runs) |
| 3 | Pod sandboxes (`/pause`, one per pod) have no metadata in Falco | open: an unlabelled `new_exe`-only episode per pod; harmless once `/pause` is in the baseline |
| 4 | The destination baseline is per node: the second pod to contact an address doesn't count it as new | by design for now; a per-image baseline is an option |
| 5 | Image pulls matched the model-free rule `credentials-then-new-destination`, see below | fixed |
| 6 | A pod's service-account token used against the API server matches the same rule, see below | open |
| 7 | classify reassesses an episode when it gains signals (here a connection 2 s after a file read), so one episode can have several records | by design; the checks use each episode's last record, and "never matches" checks use all of them |
| 8 | Falco's catch-all rule missed ping: Falco reports ICMP and raw sockets as connected, which the rule excluded | fixed: ICMP and raw sends are reported once per destination; a pod's ping to a decoy address now matches `decoy-contacted` |

**Finding 5, image pulls.** containerd, unpacking an image, writes the image's own
`/etc/shadow`, `/etc/profile` and crontab under
`/var/lib/rancher/k3s/agent/containerd/…/snapshots/<n>/fs/etc/` (3 credential and 6
persistence hits in one pull), and connects to the registry. This happens for every new
image a node pulls. Fix: writes inside container runtime storage (`/var/lib/containerd/`,
`/var/lib/docker/`, `/var/lib/containers/`, k3s's containerd) get no category. Reads there
keep theirs: the host reading a container's secrets is still credential access. The test
imports a fresh one-layer image each run (a pulled image can share layers already on disk,
and then nothing is unpacked) and checks the unpack is seen and matches nothing.

**Finding 6, service-account token.** A k3s system job (`helm`, `kube-system`) read
`/var/run/secrets/kubernetes.io/serviceaccount/token` and connected to the API server
(`10.43.0.1:443`), which counted as a new destination (the test runs with `--learn 0`).
Every pod that talks to the API looks like this. With a learning period, the API server's
address is learned from the first pods that use it, so this mostly affects a fresh node.
Seen only on the first run: k3s runs that job once. Possible fixes: treat the token used
only against the API server as normal, or keep the baseline per image.

## Not tested

Several nodes, CRI-O, and dnom's own collector on a node (its events carry cgroup ids,
which aren't mapped to pods yet).
