acls:a
  allow_server:
    # h1 -> server
    - rule:
        dl_type: 0x0800
        ip_proto: 6
        ipv4_src: 10.0.0.1
        ipv4_dst: 10.0.0.11
        actions:
          allow: 1

    # server -> h1
    - rule:
        dl_type: 0x0800
        ip_proto: 6
        ipv4_src: 10.0.0.11
        ipv4_dst: 10.0.0.1
        actions:
          allow: 1

    # h2 -> server
    - rule:
        dl_type: 0x0800
        ip_proto: 6
        ipv4_src: 10.0.0.2
        ipv4_dst: 10.0.0.11
        actions:
          allow: 1

    # server -> h2
    - rule:
        dl_type: 0x0800
        ip_proto: 6
        ipv4_src: 10.0.0.11
        ipv4_dst: 10.0.0.2
        actions:
          allow: 1

    # mgmt -> server
    - rule:
        dl_type: 0x0800
        ip_proto: 6
        ipv4_src: 10.0.0.254
        ipv4_dst: 10.0.0.11
        actions:
          allow: 1

    # server -> mgmt
    - rule:
        dl_type: 0x0800
        ip_proto: 6
        ipv4_src: 10.0.0.11
        ipv4_dst: 10.0.0.254
        actions:
          allow: 1

    # DROP EVERYTHING ELSE
    - rule:
        actions:
          drop: 1
