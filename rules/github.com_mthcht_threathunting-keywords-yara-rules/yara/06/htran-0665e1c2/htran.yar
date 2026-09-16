rule htran
{
    meta:
        description = "Detection patterns for the tool 'htran' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "htran"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Hacktool\.HTran\./ nocase ascii wide
                        $string2 = "HackTool:Win32/Htran" nocase ascii wide
                        $string3 = "HKTL_HTRAN" nocase ascii wide
                        $string4 = "Riskware/Htran" nocase ascii wide
                        $string5 = /Win32\/HackTool\.Hucline\.F/ nocase ascii wide

    condition:
        any of them
}