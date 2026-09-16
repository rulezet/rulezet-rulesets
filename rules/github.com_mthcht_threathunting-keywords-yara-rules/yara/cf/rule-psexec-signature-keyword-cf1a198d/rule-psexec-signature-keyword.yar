rule rule_psexec_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'psexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psexec"
        rule_category = "signature_keyword"

    strings:
                        $string1_psexec_signature_keyword = "VirTool:Win32/RemoteExec" nocase ascii wide
                        $string2_psexec_signature_keyword = "VirTool:Win64/RemoteExec" nocase ascii wide

    condition:
        any of them
}