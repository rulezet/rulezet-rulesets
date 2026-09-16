rule Privileger
{
    meta:
        description = "Detection patterns for the tool 'Privileger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Privileger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Privileger\.git/ nocase ascii wide
                        $string2 = "MzHmO/Privileger" nocase ascii wide
                        $string3 = /Privileger\.cpp/ nocase ascii wide
                        $string4 = /Privileger\.exe/ nocase ascii wide
                        $string5 = /Privileger\-main\./ nocase ascii wide
                        $string6 = /Privilegerx64\.exe/ nocase ascii wide
                        $string7 = /Privilegerx86\.exe/ nocase ascii wide

    condition:
        any of them
}