rule commix
{
    meta:
        description = "Detection patterns for the tool 'commix' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "commix"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/commix\.git/ nocase ascii wide
                        $string2 = /\/commix\.py/ nocase ascii wide
                        $string3 = "commixproject/commix" nocase ascii wide

    condition:
        any of them
}