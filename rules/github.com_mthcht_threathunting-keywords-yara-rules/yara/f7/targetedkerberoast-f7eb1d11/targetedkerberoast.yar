rule targetedKerberoast
{
    meta:
        description = "Detection patterns for the tool 'targetedKerberoast' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "targetedKerberoast"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/targetedKerberoast" nocase ascii wide
                        $string2 = /kerberoastables\.txt/ nocase ascii wide
                        $string3 = /targetedKerberoast\.git/ nocase ascii wide
                        $string4 = /targetedKerberoast\.py/ nocase ascii wide
                        $string5 = "targetedKerberoast-main" nocase ascii wide

    condition:
        any of them
}