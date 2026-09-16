rule rule_asleap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'asleap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "asleap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_asleap_offensive_tool_keyword = /\/asleap\.exe/ nocase ascii wide
                        $string2_asleap_offensive_tool_keyword = /\\asleap\.exe/ nocase ascii wide
                        $string3_asleap_offensive_tool_keyword = "apt install asleap" nocase ascii wide
                        $string4_asleap_offensive_tool_keyword = /asleap\s\-C\s.{0,1000}\s\-R\s/ nocase ascii wide
                        $string5_asleap_offensive_tool_keyword = /asleap\s\-r\s.{0,1000}\.dump\s/ nocase ascii wide
                        $string6_asleap_offensive_tool_keyword = /https\:\/\/gitlab\.com\/kalilinux\/packages\/asleap/

    condition:
        any of them
}