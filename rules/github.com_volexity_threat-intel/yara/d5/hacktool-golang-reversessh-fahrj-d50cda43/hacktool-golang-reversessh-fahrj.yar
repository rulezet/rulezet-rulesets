rule hacktool_golang_reversessh_fahrj
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Detects a reverse SSH utility available on GitHub. Attackers may use this tool or similar tools in post-exploitation activity."
        hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/Fahrj/reverse-ssh"
        report = "TIB-20240412"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-04-12T13:06:01Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10423
        version = 5

    strings:
        $fun_1 = "createLocalPortForwardingCallback"
        $fun_2 = "createReversePortForwardingCallback"
        $fun_3 = "createPasswordHandler"
        $fun_4 = "createPublicKeyHandler"
        $fun_5 = "createSFTPHandler"
        $fun_6 = "dialHomeAndListen"
        $fun_7 = "createExtraInfoHandler"
        $fun_8 = "createSSHSessionHandler"
        $fun_9 = "createReversePortForwardingCallback"

        $proj_1 = "github.com/Fahrj/reverse-ssh"

    condition:
        any of ($proj_*) or
        4 of ($fun_*)
}