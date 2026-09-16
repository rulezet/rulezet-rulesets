rule supershell
{
    meta:
        description = "Detection patterns for the tool 'supershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "supershell"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "http://localhost:7681" nocase ascii wide
                        $string2 = /ttyd\s\-i\s0\.0\.0\.0\s\-p\s7681\s/ nocase ascii wide
                        $string3 = /ttyd\s\-i\s0\.0\.0\.0\s\-p\s7682\s/ nocase ascii wide

    condition:
        any of them
}