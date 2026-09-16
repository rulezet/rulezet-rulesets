rule susp_any_gost_arguments
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Looks for common arguments passed to the hacktool GOST that are sometimes used by attackers in scripts (for example cronjobs etc)."
        os = "all"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-04-12T13:06:14Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10425
        version = 2

    strings:
        $s1 = "-L=socks5://" ascii
        $s2 = "-L rtcp://" ascii

    condition:
        filesize < 10KB and
        any of them
}