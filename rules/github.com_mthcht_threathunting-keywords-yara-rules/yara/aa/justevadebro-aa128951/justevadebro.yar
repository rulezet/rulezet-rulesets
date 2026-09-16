rule JustEvadeBro
{
    meta:
        description = "Detection patterns for the tool 'JustEvadeBro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JustEvadeBro"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\spapacat\.ps1/ nocase ascii wide
                        $string2 = /\/papacat\.zip/ nocase ascii wide
                        $string3 = /\\papacat\.ps1/ nocase ascii wide
                        $string4 = /\\papacat\.zip/ nocase ascii wide
                        $string5 = "aQBlAHgAIAAoAE4AZwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAvAHIAZQB2AC4AcABzADEAJwApAA" nocase ascii wide
                        $string6 = "papacat -l -p " nocase ascii wide

    condition:
        any of them
}