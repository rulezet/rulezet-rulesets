rule Suborner
{
    meta:
        description = "Detection patterns for the tool 'Suborner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Suborner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Suborner\.git/ nocase ascii wide
                        $string2 = /\\Suborner\.sln/ nocase ascii wide
                        $string3 = "r4wd3r/Suborner" nocase ascii wide
                        $string4 = /Suborner\.exe/ nocase ascii wide
                        $string5 = /Suborner\-master\.zip/ nocase ascii wide

    condition:
        any of them
}