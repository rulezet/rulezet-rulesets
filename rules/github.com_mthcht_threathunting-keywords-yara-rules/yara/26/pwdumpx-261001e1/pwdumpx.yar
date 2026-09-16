rule PWDumpX
{
    meta:
        description = "Detection patterns for the tool 'PWDumpX' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWDumpX"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HKTL_PWDUMP\./ nocase ascii wide
                        $string2 = /PSWTool\.Win32\.PWDump/ nocase ascii wide
                        $string3 = "PWCrack-PWDump" nocase ascii wide
                        $string4 = /PWDumpX\s\(PUA\)/ nocase ascii wide

    condition:
        any of them
}