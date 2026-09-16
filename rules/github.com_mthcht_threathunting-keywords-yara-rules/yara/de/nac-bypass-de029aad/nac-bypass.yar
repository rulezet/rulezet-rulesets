rule nac_bypass
{
    meta:
        description = "Detection patterns for the tool 'nac_bypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nac_bypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "nac_bypass" nocase ascii wide

    condition:
        any of them
}