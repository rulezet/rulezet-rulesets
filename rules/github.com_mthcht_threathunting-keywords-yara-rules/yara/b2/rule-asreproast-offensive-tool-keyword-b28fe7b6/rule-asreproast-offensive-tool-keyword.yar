rule rule_ASREPRoast_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ASREPRoast' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ASREPRoast"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ASREPRoast_offensive_tool_keyword = "/ASREPRoast" nocase ascii wide
                        $string2_ASREPRoast_offensive_tool_keyword = /ASREPRoast\.ps1/ nocase ascii wide
                        $string3_ASREPRoast_offensive_tool_keyword = "crackTGS" nocase ascii wide
                        $string4_ASREPRoast_offensive_tool_keyword = "Invoke-ASREPRoast" nocase ascii wide
                        $string5_ASREPRoast_offensive_tool_keyword = /tgscrack\.go/ nocase ascii wide

    condition:
        any of them
}