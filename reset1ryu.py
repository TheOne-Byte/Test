acls:
  allow_server:
    # h1 <-> server
    - rule:
        dl_type: 0x0800
        nw_proto: 6
        ipv4_src: 10.0.0.1
        ipv4_dst: 10.0.0.11
        allow: 1
    - rule:
        dl_type: 0x0800
        nw_proto: 6
        ipv4_src: 10.0.0.11
        ipv4_dst: 10.0.0.1
        allow: 1

    # h2 <-> server
    - rule:
        dl_type: 0x0800
        nw_proto: 6
        ipv4_src: 10.0.0.2
        ipv4_dst: 10.0.0.11
        allow: 1
    - rule:
        dl_type: 0x0800
        nw_proto: 6
        ipv4_src: 10.0.0.11
        ipv4_dst: 10.0.0.2
        allow: 1

    # mgmt <-> server
    - rule:
        dl_type: 0x0800
        nw_proto: 6
        ipv4_src: 10.0.0.254
        ipv4_dst: 10.0.0.11
        allow: 1
    - rule:
        dl_type: 0x0800
        nw_proto: 6
        ipv4_src: 10.0.0.11
        ipv4_dst: 10.0.0.254
        allow: 1

    # Drop everything else
    - rule:
        drop: 1
