rule rule_PWDumpX_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'PWDumpX' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWDumpX"
        rule_category = "signature_keyword"

    strings:
                        $string1_PWDumpX_signature_keyword = /HKTL_PWDUMP\./ nocase ascii wide
                        $string2_PWDumpX_signature_keyword = /PSWTool\.Win32\.PWDump/ nocase ascii wide
                        $string3_PWDumpX_signature_keyword = "PWCrack-PWDump" nocase ascii wide
                        $string4_PWDumpX_signature_keyword = /PWDumpX\s\(PUA\)/ nocase ascii wide

    condition:
        any of them
}