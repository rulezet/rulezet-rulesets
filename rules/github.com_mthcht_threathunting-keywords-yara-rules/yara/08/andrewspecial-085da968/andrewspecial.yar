rule AndrewSpecial
{
    meta:
        description = "Detection patterns for the tool 'AndrewSpecial' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AndrewSpecial"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AndrewSpecial\.git/ nocase ascii wide
                        $string2 = /\\Andrew\.dmp/ nocase ascii wide
                        $string3 = /AndrewSpecial\.cpp/ nocase ascii wide
                        $string4 = /AndrewSpecial\.exe/ nocase ascii wide
                        $string5 = "AndrewSpecial-master" nocase ascii wide
                        $string6 = "hoangprod/AndrewSpecial" nocase ascii wide

    condition:
        any of them
}