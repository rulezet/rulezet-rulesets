rule katoolin3
{
    meta:
        description = "Detection patterns for the tool 'katoolin3' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "katoolin3"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/katoolin3"
                        $string2 = "/s-h-3-l-l/"
                        $string3 = "cd katoolin3"
                        $string4 = /katoolin.{0,1000}toollist\.py/
                        $string5 = /katoolin3\.py/

    condition:
        any of them
}