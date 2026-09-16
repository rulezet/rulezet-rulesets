rule rule_boko_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'boko' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "boko"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_boko_offensive_tool_keyword = "/bashexplode/boko"
                        $string2_boko_offensive_tool_keyword = /\/boko\.py/ nocase ascii wide
                        $string3_boko_offensive_tool_keyword = "BackdoorableScript" nocase ascii wide
                        $string4_boko_offensive_tool_keyword = /boko\.py\s/ nocase ascii wide
                        $string5_boko_offensive_tool_keyword = /bokoscanner\./ nocase ascii wide
                        $string6_boko_offensive_tool_keyword = "import boko" nocase ascii wide

    condition:
        any of them
}