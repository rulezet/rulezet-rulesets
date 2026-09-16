rule rule_o365spray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'o365spray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365spray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_o365spray_offensive_tool_keyword = /\so365spray\.py/ nocase ascii wide
                        $string2_o365spray_offensive_tool_keyword = /\/o365spray\.git/ nocase ascii wide
                        $string3_o365spray_offensive_tool_keyword = /\/o365spray\.py/ nocase ascii wide
                        $string4_o365spray_offensive_tool_keyword = /\\o365spray\.py/ nocase ascii wide
                        $string5_o365spray_offensive_tool_keyword = "0xZDH/o365spray" nocase ascii wide
                        $string6_o365spray_offensive_tool_keyword = "d4ba2464d2d3450db40ac57c7e0d6d7a7e4ac72c44cbd6ce9e4b3366f3a8907b" nocase ascii wide
                        $string7_o365spray_offensive_tool_keyword = /from\so365spray\.__main__/ nocase ascii wide
                        $string8_o365spray_offensive_tool_keyword = /from\so365spray\.core\.utils/ nocase ascii wide
                        $string9_o365spray_offensive_tool_keyword = "Invoke-AzureAdPasswordSprayAttack" nocase ascii wide
                        $string10_o365spray_offensive_tool_keyword = "o365spray --enum " nocase ascii wide
                        $string11_o365spray_offensive_tool_keyword = "o365spray --spray " nocase ascii wide
                        $string12_o365spray_offensive_tool_keyword = "o365spray --validate" nocase ascii wide
                        $string13_o365spray_offensive_tool_keyword = /o365spray\.core\.handlers\.sprayer/ nocase ascii wide
                        $string14_o365spray_offensive_tool_keyword = "Password spraying using paired usernames:passwords" nocase ascii wide
                        $string15_o365spray_offensive_tool_keyword = "Running password spray against %d users" nocase ascii wide

    condition:
        any of them
}