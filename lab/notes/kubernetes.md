# Kubernetes lab run (k3s, 2026-11-09)

Does pod and namespace context reach dnom's episodes and policies on a real cluster?
Reproduce with `make vm-start && make vm-k3s` (14 checks; results in
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
| 5 | False alarms from the model-free rule `credentials-then-new-destination` on a fresh node, see below | open |

Finding 5, first run only (the second run, with images cached, had none):

1. **Service-account token + API server.** A k3s system job (`helm`, `kube-system`) read
   `/var/run/secrets/kubernetes.io/serviceaccount/token` and connected to the API server
   (`10.43.0.1:443`). Every pod that talks to the API looks like this.
2. **Image pulls.** containerd, unpacking an image, writes the image's own `/etc/shadow`
   under `/var/lib/rancher/k3s/agent/containerd/…/snapshots/<n>/fs/etc/`, and connects to
   the registry (Docker Hub). This happens on every new image a node pulls.

Possible fixes, not decided: count credential reads only (the pull is a write); treat the
service-account token used only against the API server as normal; keep the baseline per
image instead of per node.

## Not tested

Several nodes, CRI-O, and dnom's own collector on a node (its events carry cgroup ids,
which aren't mapped to pods yet).
