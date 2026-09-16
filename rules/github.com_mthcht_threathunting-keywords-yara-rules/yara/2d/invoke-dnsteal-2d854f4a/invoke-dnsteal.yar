rule Invoke_DNSteal
{
    meta:
        description = "Detection patterns for the tool 'Invoke-DNSteal' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-DNSteal"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "2dd67e996df7577217a7fcc783610a7bb901655e1ce269157c6d935ea0dd510c" nocase ascii wide
                        $string2 = "94519aa5c41e7294ffc95b621e39097172fd0eeb9287d8678346fb80898516c3" nocase ascii wide
                        $string3 = "Invoke-DNSteal" nocase ascii wide

    condition:
        any of them
}