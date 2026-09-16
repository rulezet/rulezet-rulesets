rule ADCSKiller
{
    meta:
        description = "Detection patterns for the tool 'ADCSKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSKiller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ADCSKiller" nocase ascii wide
                        $string2 = /adcskiller\.py/ nocase ascii wide
                        $string3 = "ly4k/Certipy" nocase ascii wide
                        $string4 = "p0dalirius/Coercer" nocase ascii wide

    condition:
        any of them
}