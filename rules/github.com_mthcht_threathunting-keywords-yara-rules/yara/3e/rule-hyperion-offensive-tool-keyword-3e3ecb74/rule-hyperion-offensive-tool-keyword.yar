rule rule_hyperion_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hyperion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hyperion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hyperion_offensive_tool_keyword = /\/hyperion\.exe/ nocase ascii wide
                        $string2_hyperion_offensive_tool_keyword = "/windows-resources/hyperion" nocase ascii wide
                        $string3_hyperion_offensive_tool_keyword = /\\hyperion\.exe/ nocase ascii wide
                        $string4_hyperion_offensive_tool_keyword = "apt install hyperion" nocase ascii wide
                        $string5_hyperion_offensive_tool_keyword = "Hyperion PE-Crypter" nocase ascii wide
                        $string6_hyperion_offensive_tool_keyword = /hyperion\.exe\s/ nocase ascii wide
                        $string7_hyperion_offensive_tool_keyword = /hyperion_2\.0\.orig\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}