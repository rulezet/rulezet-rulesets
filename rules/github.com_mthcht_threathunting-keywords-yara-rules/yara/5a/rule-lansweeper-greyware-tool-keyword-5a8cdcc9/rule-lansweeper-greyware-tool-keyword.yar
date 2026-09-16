rule rule_Lansweeper_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lansweeper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lansweeper"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Lansweeper_greyware_tool_keyword = /\/LansweeperSetup_.{0,1000}\.exe/ nocase ascii wide
                        $string2_Lansweeper_greyware_tool_keyword = /\\AppData\\Local\\Temp\\lansweeper\-/ nocase ascii wide
                        $string3_Lansweeper_greyware_tool_keyword = /\\LansweeperService\.exe/ nocase ascii wide
                        $string4_Lansweeper_greyware_tool_keyword = /\\LansweeperSetup_.{0,1000}\.exe/ nocase ascii wide
                        $string5_Lansweeper_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Lansweeper/ nocase ascii wide
                        $string6_Lansweeper_greyware_tool_keyword = ">Lansweeper Setup<" nocase ascii wide
                        $string7_Lansweeper_greyware_tool_keyword = ">Lansweeper<" nocase ascii wide
                        $string8_Lansweeper_greyware_tool_keyword = /https\:\/\/update\.lansweeper\.com\/installation\.aspx/ nocase ascii wide
                        $string9_Lansweeper_greyware_tool_keyword = /https\:\/\/www\.lansweeper\.com\/installation\.aspx/ nocase ascii wide

    condition:
        any of them
}