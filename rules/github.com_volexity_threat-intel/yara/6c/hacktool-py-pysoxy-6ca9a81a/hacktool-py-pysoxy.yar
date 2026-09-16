rule hacktool_py_pysoxy
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-01-09"
        description = "SOCKS5 proxy tool used to relay connections."
        hash1 = "e192932d834292478c9b1032543c53edfc2b252fdf7e27e4c438f4b249544eeb"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/MisterDaneel/pysoxy/blob/master/pysoxy.py"
        report = "TIB-20240109"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-01-09T13:45:28Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10065
        version = 3

    strings:
        $s1 = "proxy_loop" ascii
        $s2 = "connect_to_dst" ascii
        $s3 = "request_client" ascii
        $s4 = "subnegotiation_client" ascii
        $s5 = "bind_port" ascii

    condition:
        all of them
}