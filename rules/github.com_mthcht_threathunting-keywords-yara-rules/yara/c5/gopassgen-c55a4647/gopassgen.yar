rule goPassGen
{
    meta:
        description = "Detection patterns for the tool 'goPassGen' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goPassGen"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/goPassGen\.git/ nocase ascii wide
                        $string2 = "bigb0sss/goPassGen" nocase ascii wide
                        $string3 = "goPassGen-master" nocase ascii wide

    condition:
        any of them
}