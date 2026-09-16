rule teamstracker
{
    meta:
        description = "Detection patterns for the tool 'teamstracker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teamstracker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\steamstracker\.py/ nocase ascii wide
                        $string2 = /\/teamstracker\.db/ nocase ascii wide
                        $string3 = /\/teamstracker\.git/ nocase ascii wide
                        $string4 = /\/teamstracker\.py/ nocase ascii wide
                        $string5 = /\\teamstracker\.py/ nocase ascii wide
                        $string6 = "nyxgeek/teamstracker" nocase ascii wide
                        $string7 = "teamstracker-main" nocase ascii wide

    condition:
        any of them
}