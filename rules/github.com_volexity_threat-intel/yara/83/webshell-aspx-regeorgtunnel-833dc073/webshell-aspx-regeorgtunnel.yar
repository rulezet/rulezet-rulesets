rule webshell_aspx_reGeorgTunnel
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-02"
        description = "A variation of the reGeorgtunnel open-source webshell."
        hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
        os = "win"
        os_arch = "all"
        reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
        scan_context = "file,memory"
        severity = "high"
        last_modified = "2024-10-18T13:43:52Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 4979
        version = 4

    strings:
        $s1 = "System.Net.Sockets"
        $s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"

        $t1 = ".Split('|')"
        $t2 = "Request.Headers.Get"
        $t3 = ".Substring("
        $t4 = "new Socket("
        $t5 = "IPAddress ip;"

    condition:
        all of ($s*) or
        all of ($t*)
}