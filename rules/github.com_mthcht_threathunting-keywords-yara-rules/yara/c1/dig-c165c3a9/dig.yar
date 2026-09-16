rule dig
{
    meta:
        description = "Detection patterns for the tool 'dig' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dig"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /dig\s.{0,1000}\saxfr\s.{0,1000}\@/ nocase ascii wide
                        $string2 = /dig\s.{0,1000}\@.{0,1000}\saxfr/ nocase ascii wide

    condition:
        any of them
}