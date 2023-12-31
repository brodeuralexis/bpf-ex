BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET_INGRESS, "cgroup_inet_ingress")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET_EGRESS, "cgroup_inet_egress")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET_SOCK_CREATE, "cgroup_inet_sock_create")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_SOCK_OPS, "cgroup_sock_ops")
BPF_SYS_ATTACH_TYPE(BPF_SK_SKB_STREAM_PARSER, "sk_skb_stream_parser")
BPF_SYS_ATTACH_TYPE(BPF_SK_SKB_STREAM_VERDICT, "sk_skb_stream_verdict")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_DEVICE, "cgroup_device")
BPF_SYS_ATTACH_TYPE(BPF_SK_MSG_VERDICT, "sk_msg_verdict")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET4_BIND, "cgroup_inet4_bind")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET6_BIND, "cgroup_inet6_bind")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET4_CONNECT, "cgroup_inet4_connect")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET6_CONNECT, "cgroup_inet6_connect")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET4_POST_BIND, "cgroup_inet4_post_bind")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET6_POST_BIND, "cgroup_inet6_post_bind")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_UDP4_SENDMSG, "cgroup_udp4_sendmsg")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_UDP6_SENDMSG, "cgroup_udp6_sendmsg")
BPF_SYS_ATTACH_TYPE(BPF_LIRC_MODE2, "lirc_mode2")
BPF_SYS_ATTACH_TYPE(BPF_FLOW_DISSECTOR, "flow_dissector")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_SYSCTL, "cgroup_sysctl")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_UDP4_RECVMSG, "cgroup_udp4_recvmsg")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_UDP6_RECVMSG, "cgroup_udp6_recvmsg")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_GETSOCKOPT, "cgroup_getsockopt")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_SETSOCKOPT, "cgroup_setsockopt")
BPF_SYS_ATTACH_TYPE(BPF_TRACE_RAW_TP, "trace_raw_tp")
BPF_SYS_ATTACH_TYPE(BPF_TRACE_FENTRY, "trace_fentry")
BPF_SYS_ATTACH_TYPE(BPF_TRACE_FEXIT, "trace_fexit")
BPF_SYS_ATTACH_TYPE(BPF_MODIFY_RETURN, "modify_return")
BPF_SYS_ATTACH_TYPE(BPF_LSM_MAC, "lsm_mac")
BPF_SYS_ATTACH_TYPE(BPF_TRACE_ITER, "trace_iter")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET4_GETPEERNAME, "cgroup_inet4_getpeername")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET6_GETPEERNAME, "cgroup_inet6_getpeername")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET4_GETSOCKNAME, "cgroup_inet4_getsockname")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET6_GETSOCKNAME, "cgroup_inet6_getsockname")
BPF_SYS_ATTACH_TYPE(BPF_XDP_DEVMAP, "xdp_devmap")
BPF_SYS_ATTACH_TYPE(BPF_CGROUP_INET_SOCK_RELEASE, "cgroup_inet_sock_release")
BPF_SYS_ATTACH_TYPE(BPF_XDP_CPUMAP, "xdp_cpumap")
BPF_SYS_ATTACH_TYPE(BPF_SK_LOOKUP, "sk_lookup")
BPF_SYS_ATTACH_TYPE(BPF_XDP, "xdp")
BPF_SYS_ATTACH_TYPE(BPF_SK_SKB_VERDICT, "sk_skb_verdict")
BPF_SYS_ATTACH_TYPE(BPF_SK_REUSEPORT_SELECT, "sk_reuseport_select")
BPF_SYS_ATTACH_TYPE(BPF_SK_REUSEPORT_SELECT_OR_MIGRATE, "sk_reuseport_select_or_migrate")
BPF_SYS_ATTACH_TYPE(BPF_PERF_EVENT, "perf_event")
BPF_SYS_ATTACH_TYPE(BPF_TRACE_KPROBE_MULTI, "trace_kprobe_multi")
BPF_SYS_ATTACH_TYPE(BPF_LSM_CGROUP, "lsm_cgroup")
