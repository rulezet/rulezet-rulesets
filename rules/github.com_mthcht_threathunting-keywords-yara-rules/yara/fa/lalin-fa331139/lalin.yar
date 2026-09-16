rule LALIN
{
    meta:
        description = "Detection patterns for the tool 'LALIN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LALIN"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sLalin\.sh/ nocase ascii wide
                        $string2 = /\.\/Lalin\.sh/
                        $string3 = /Lalin\.sh\s/
                        $string4 = /lazynmap\.sh/ nocase ascii wide

    condition:
        any of them
}