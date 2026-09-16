rule Gorsair
{
    meta:
        description = "Detection patterns for the tool 'Gorsair' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gorsair"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/bin/gorsair "
                        $string2 = /\/gorsair\.go/ nocase ascii wide
                        $string3 = "gorsair -t " nocase ascii wide
                        $string4 = "Ullaakut/Gorsair" nocase ascii wide

    condition:
        any of them
}