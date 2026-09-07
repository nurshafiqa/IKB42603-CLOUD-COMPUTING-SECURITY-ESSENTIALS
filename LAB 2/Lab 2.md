# Lab 2: Secure Isolation & Multi-Tenancy

**Course:** IKB42603 Cloud Computing Security Essentials  
**Topic:** Compute, network and storage isolation, default-deny NetworkPolicy, RBAC secret isolation, and data remanence  
**Environment:** kind Kubernetes cluster `ccse-lab2` with Calico CNI and Docker

---

## Lab Summary / Objective

This lab demonstrates secure multi-tenant isolation on shared cloud infrastructure using Kubernetes and Docker.

The lab covers three major isolation dimensions:

- **Compute isolation** by separating two simulated tenants into Kubernetes namespaces and applying a `ResourceQuota`.
- **Network isolation** by observing the default-open behaviour between namespaces and then applying a default-deny `NetworkPolicy`.
- **Storage and secret isolation** by using Kubernetes RBAC so that a service account in one tenant cannot access another tenant's Secret.
- **Data remanence** by demonstrating normal deletion and secure overwriting before deletion using a Docker volume.

The lab is divided into two sessions:

- **Session A (Week 3):** Tasks 1–3 — compute isolation, default-open risk, and resource quotas.
- **Session B (Week 4):** Tasks 4–6 — network isolation, secret isolation, and data remanence.

---

## Architecture Diagram

```text
                         Kubernetes Cluster
                             ccse-lab2
                           Calico CNI
                                |
                +---------------+---------------+
                |                               |
          Namespace: tenant-a             Namespace: tenant-b
                |                               |
            nginx web                       nginx web
                |                               |
             Service                         Service
                |                               |
        ResourceQuota                  default-deny
        tenant-a-quota                NetworkPolicy
                |                               |
        ServiceAccount                  Secret: data
             app-a
                |
          Role: reader
                |
          RoleBinding rb
                |
             Secrets

              Tenant A  -------- X -------->  Tenant B
                       Network isolation
```

---

# Session A — Compute Isolation & Default-Open Risk

## Environment Setup — kind + Calico

A kind cluster named `ccse-lab2` was created with the default CNI disabled. Calico was then installed to provide NetworkPolicy enforcement.

```powershell
@"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
"@ | kind create cluster --name ccse-lab2 --config=-
```

Calico was installed using:

```powershell
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
kubectl get nodes
```

### Result

The cluster was successfully created and Calico successfully rolled out. The Kubernetes control-plane node reached the `Ready` state.

### Evidence

![Cluster creation](evidence%20lab2/setup1.1.png)

![Initial node status](evidence%20lab2/setup1.2.png)

![Calico rollout and node Ready](evidence%20lab2/setup2.png)

---

# Task 1 — Two Tenants on One Cluster

Two namespaces were used to model two customers sharing the same physical Kubernetes infrastructure.

```powershell
kubectl create namespace tenant-a
kubectl create namespace tenant-b
```

Nginx web applications were deployed for both tenants:

```powershell
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
```

The deployments were exposed as Services:

```powershell
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
```

The resulting workloads were checked with:

```powershell
kubectl get pods,svc -n tenant-a
kubectl get pods,svc -n tenant-b
```

### Result

Both tenants had a running nginx Pod and a ClusterIP Service.

**Tenant A:**
- Pod: `web-5fc9f4bf66-mxqqv`
- Status: `Running`
- Service ClusterIP: `10.96.126.68`
- Port: `80/TCP`

**Tenant B:**
- Pod: `web-5fc9f4bf66-p7wff`
- Status: `Running`
- Service ClusterIP: `10.96.43.141`
- Port: `80/TCP`

### Evidence

![Task 1 - Tenant A and Tenant B Pods and Services](evidence%20lab2/task1.png)

---

# Task 2 — Observe the Default-Open Risk

The ClusterIP of Tenant B's Service was obtained:

```powershell
kubectl get svc web -n tenant-b -o jsonpath="{.spec.clusterIP}"
```

Result:

```text
10.96.43.141
```

A probe was then launched from `tenant-a` to Tenant B's Service:

```powershell
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never -- curl -s -m 5 http://10.96.43.141 -o /dev/null -w "HTTP %{http_code}\n"
```

### Result

The probe returned:

```text
HTTP 200
```

This proved that a workload in `tenant-a` could reach the Service in `tenant-b` before a NetworkPolicy was applied.

This demonstrates that Kubernetes namespaces provide logical separation but do not automatically provide network isolation.

### Evidence

![Task 2 - Cross-tenant HTTP 200](evidence%20lab2/task2.png)

---

# Task 3 — Contain the Noisy Neighbour with ResourceQuota

A ResourceQuota was created for `tenant-a`:

```powershell
kubectl create quota tenant-a-quota --hard=pods=5,requests.cpu=1,requests.memory=512Mi -n tenant-a
```

The quota was verified using:

```powershell
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

### Configured Limits

| Resource | Hard Limit |
|---|---:|
| Pods | `5` |
| CPU requests | `1` |
| Memory requests | `512Mi` |

### Result

The quota was successfully created. At verification time, one Pod was counted against the quota, while CPU and memory requests were below their configured limits.

The ResourceQuota prevents a tenant from consuming unlimited shared Kubernetes resources and helps reduce noisy-neighbour problems.

### Evidence

![Task 3 - ResourceQuota](evidence%20lab2/task3.png)

---

# Session B — Network & Storage Isolation

# Task 4 — Default-Deny Network Isolation

A default-deny ingress NetworkPolicy was applied to `tenant-b`:

```powershell
@"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes:
    - Ingress
"@ | kubectl apply -f -
```

The policy was verified using:

```powershell
kubectl get networkpolicy -n tenant-b
kubectl describe networkpolicy default-deny-ingress -n tenant-b
```

The policy selected all Pods in `tenant-b` and specified `Ingress` as the policy type without allowing any ingress sources.

### Before the Policy

The cross-tenant probe from Task 2 returned:

```text
HTTP 200
```

### After the Policy

Because the ResourceQuota requires CPU and memory requests for new Pods, a probe Pod was created with explicit resource requests:

```powershell
@"
apiVersion: v1
kind: Pod
metadata:
  name: probe
  namespace: tenant-a
spec:
  restartPolicy: Never
  containers:
    - name: probe
      image: curlimages/curl
      resources:
        requests:
          cpu: 100m
          memory: 64Mi
      command:
        - curl
        - -s
        - -m
        - "5"
        - http://10.96.43.141
        - -o
        - /dev/null
        - -w
        - "HTTP %{http_code}\n"
"@ | kubectl apply -f -
```

The result was checked with:

```powershell
kubectl logs probe -n tenant-a
```

Result:

```text
HTTP 000
```

### Result

The before-and-after comparison demonstrates network isolation:

| Test | Result |
|---|---|
| Before NetworkPolicy | `HTTP 200` |
| After NetworkPolicy | `HTTP 000` |

The NetworkPolicy successfully prevented the cross-tenant HTTP connection.

### Evidence

**Policy configuration:**

![Task 4.1 - Default-deny NetworkPolicy](evidence%20lab2/task4.1.png)

**Blocked probe:**

![Task 4.2 - Cross-tenant traffic blocked](evidence%20lab2/task4.2.png)

---

# Task 5 — Storage & Secret Isolation

## Task 5.1 — Create Per-Tenant Secrets

A Secret named `data` was created in each namespace:

```powershell
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B
```

The Secrets were checked with:

```powershell
kubectl get secrets -n tenant-a
kubectl get secrets -n tenant-b
```

### Result

Both tenants had their own `data` Secret.

### Evidence

![Task 5.1 - Secrets in both tenants](evidence%20lab2/task5.1.png)

---

## Task 5.2 — RBAC Secret Isolation

A ServiceAccount was created only in `tenant-a`:

```powershell
kubectl -n tenant-a create serviceaccount app-a
```

A Role allowing the ServiceAccount to get Secrets was created:

```powershell
kubectl -n tenant-a create role reader --verb=get --resource=secrets
```

The Role was bound to `app-a`:

```powershell
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
```

The resulting RBAC objects were verified:

```powershell
kubectl get serviceaccount,role,rolebinding -n tenant-a
```

Permission checks were performed using:

```powershell
$SA="system:serviceaccount:tenant-a:app-a"
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

### Result

```text
tenant-a → yes
tenant-b → no
```

This proves that the `app-a` ServiceAccount has permission to get Secrets only within `tenant-a` and does not have permission to access Secrets in `tenant-b`.

### Evidence

![Task 5.2 - RBAC objects](evidence%20lab2/task5.2.png)

---

# Task 6 — Data Remanence & Secure Deletion

A Docker volume was created:

```powershell
docker volume create ccse-vol
```

## Task 6.1 — Normal Deletion and Remanence Scan

A sensitive file was created, synchronized, deleted normally, and then scanned:

```powershell
docker run --rm -v ccse-vol:/data alpine sh -c 'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```

### Result

The scan completed with:

```text
scan-done
```

No `SENSITIVE-PATIENT-RECORD` content was recovered by the scan in this environment.

This demonstrates that recoverability after logical deletion is dependent on the underlying filesystem and storage implementation. The test should not be interpreted as proving that deleted data can never be recovered.

### Evidence

![Task 6.1 - Normal deletion and remanence scan](evidence%20lab2/task6.1.png)

---

## Task 6.2 — Secure Wipe

The second file was overwritten with zeros before deletion:

```powershell
docker run --rm -v ccse-vol:/data alpine sh -c 'echo SENSITIVE > /data/phi2.txt; sync; dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; echo wiped'
```

### Result

The command reported:

```text
1+0 records in
1+0 records out
1024 bytes (1.0KB) copied
wiped
```

The sensitive content was overwritten before deletion.

In real cloud storage, physical block control is normally unavailable to the customer. Therefore, cryptographic erasure is a more practical approach because destroying the encryption key can make the encrypted data inaccessible.

### Evidence

![Task 6.2 - Secure wipe](evidence%20lab2/task6.2.png)

---

# Final Verification

The NetworkPolicy was verified:

```powershell
kubectl get networkpolicy -A
```

Result included:

```text
tenant-b    default-deny-ingress    <none>
```

The ResourceQuota was verified:

```powershell
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

Current values were:

```text
pods             1 / 5
requests.cpu     0 / 1
requests.memory  0 / 512Mi
```

### Evidence

![Final verification](evidence%20lab2/verify.png)

---

# Short-Answer Questions

## Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?

Kubernetes namespaces provide logical separation of resources, but they do not automatically provide network isolation. Without a NetworkPolicy, Pods in different namespaces can communicate across the cluster.

This is dangerous in a multi-tenant cloud because a compromised workload in one tenant could potentially probe or attack services belonging to another tenant. This could result in unauthorized access or a cross-tenant security breach.

---

## Q2. Explain the default-deny principle and how your NetworkPolicy implements it.

The default-deny principle means that access is blocked unless it is explicitly permitted. It follows the principle of **deny by default and permit by exception**.

The `default-deny-ingress` NetworkPolicy selects all Pods in `tenant-b` using:

```yaml
podSelector: {}
```

It specifies:

```yaml
policyTypes:
  - Ingress
```

and contains no allowed ingress rules. Therefore, incoming traffic to the selected Pods is denied.

The effectiveness of the policy was demonstrated by the change from `HTTP 200` before the policy to `HTTP 000` after the policy.

---

## Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?

| Feature | Containers | Virtual Machines |
|---|---|---|
| Isolation mechanism | Kernel namespaces and cgroups | Hypervisor and virtualized hardware |
| Kernel | Share the host kernel | Each VM has its own kernel |
| Isolation strength | Lower | Stronger |
| Overhead | Lower | Higher |
| Main concern | Container escape or kernel vulnerability | Hypervisor or VM vulnerability |

Containers are lightweight because multiple containers share the same operating-system kernel. Virtual machines provide stronger isolation because each VM has its own kernel and is separated by a hypervisor.

A VM boundary should be added when tenants are highly untrusted and the impact of a cross-tenant compromise is high, such as hosting competing customers or executing untrusted third-party code.

---

## Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?

Data remanence is the possibility that data may remain recoverable on storage after the data has been logically deleted.

In this lab, normal deletion was followed by a scan of the Docker volume. The scan did not recover the sensitive content in this environment. However, this does not mean data remanence is impossible because recoverability depends on the filesystem and storage implementation.

Cryptographic erasure is preferred in cloud environments because users generally do not control the physical storage blocks. Destroying the encryption key can make the encrypted data inaccessible without requiring physical control of the underlying storage.

---

## Q5. Which of the three isolation dimensions did each task exercise?

| Task | Isolation Dimension | Explanation |
|---|---|---|
| Task 1 | **Compute** | Separated two tenants into different Kubernetes namespaces and deployed workloads independently. |
| Task 2 | **Network** | Demonstrated that cross-tenant traffic was allowed by default. |
| Task 3 | **Compute / Resource** | Used ResourceQuota to limit CPU, memory and Pod consumption for Tenant A. |
| Task 4 | **Network** | Used NetworkPolicy to block cross-tenant ingress traffic. |
| Task 5 | **Storage** | Used RBAC to restrict access to per-tenant Secrets. |
| Task 6 | **Storage** | Demonstrated normal deletion, possible remanence, and secure overwriting before deletion. |

---

# Security Best-Practices Checklist

- [x] Tenants are separated into distinct namespaces.
- [x] A default-deny NetworkPolicy blocks cross-tenant traffic.
- [x] ResourceQuota prevents a noisy neighbour from exhausting shared capacity.
- [x] Per-tenant Secrets are protected using RBAC.
- [x] Secure deletion and cryptographic erasure for data remanence are understood.

---

# Conclusion

This lab demonstrated that multi-tenancy isolation is not automatically provided simply by placing workloads into different Kubernetes namespaces.

The initial cross-tenant probe returned `HTTP 200`, showing the default-open network behaviour. After applying the default-deny NetworkPolicy to `tenant-b`, the same type of probe returned `HTTP 000`, demonstrating enforced network isolation.

ResourceQuota was used to limit shared resource consumption, while RBAC restricted the `app-a` ServiceAccount to Secrets in its own namespace. Finally, Docker volume experiments demonstrated normal deletion and overwriting before deletion, highlighting the importance of secure deletion and cryptographic erasure in cloud environments.

The combined controls provide isolation across compute/resource, network, and storage dimensions.

---

# References

- IKB42603 Cloud Computing Security Essentials — Lab 2: Secure Isolation & Multi-Tenancy.
- Kubernetes documentation — Network Policies.
- Calico documentation.
- Cloud Security Alliance — Security Guidance v5, Infrastructure & Networking domain.
