rule rule_JustEvadeBro_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'JustEvadeBro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JustEvadeBro"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_JustEvadeBro_offensive_tool_keyword = /\spapacat\.ps1/ nocase ascii wide
                        $string2_JustEvadeBro_offensive_tool_keyword = /\/papacat\.zip/ nocase ascii wide
                        $string3_JustEvadeBro_offensive_tool_keyword = /\\papacat\.ps1/ nocase ascii wide
                        $string4_JustEvadeBro_offensive_tool_keyword = /\\papacat\.zip/ nocase ascii wide
                        $string5_JustEvadeBro_offensive_tool_keyword = "aQBlAHgAIAAoAE4AZwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAvAHIAZQB2AC4AcABzADEAJwApAA" nocase ascii wide
                        $string6_JustEvadeBro_offensive_tool_keyword = "papacat -l -p " nocase ascii wide

    condition:
        any of them
}