rule LoGiC_NET
{
    meta:
        description = "Detection patterns for the tool 'LoGiC.NET' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LoGiC.NET"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /AnErrupTion\/LoGiC\.NET/ nocase ascii wide
                        $string2 = /LoGiC\.NET\.exe/ nocase ascii wide

    condition:
        any of them
}