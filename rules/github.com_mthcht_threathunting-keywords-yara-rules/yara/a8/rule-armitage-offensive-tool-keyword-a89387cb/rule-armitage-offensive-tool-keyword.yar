rule rule_armitage_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'armitage' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "armitage"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_armitage_offensive_tool_keyword = " install armitage" nocase ascii wide
                        $string2_armitage_offensive_tool_keyword = /\.\/teamserver\s/
                        $string3_armitage_offensive_tool_keyword = /\/armitage\.git/ nocase ascii wide
                        $string4_armitage_offensive_tool_keyword = /\/passhash\.sl/ nocase ascii wide
                        $string5_armitage_offensive_tool_keyword = /armitage\.exe/ nocase ascii wide
                        $string6_armitage_offensive_tool_keyword = /meterpreter\.sl/ nocase ascii wide

    condition:
        any of them
}