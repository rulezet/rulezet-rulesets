rule Lansweeper
{
    meta:
        description = "Detection patterns for the tool 'Lansweeper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lansweeper"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/LansweeperSetup_.{0,1000}\.exe/ nocase ascii wide
                        $string2 = /\\AppData\\Local\\Temp\\lansweeper\-/ nocase ascii wide
                        $string3 = /\\LansweeperService\.exe/ nocase ascii wide
                        $string4 = /\\LansweeperSetup_.{0,1000}\.exe/ nocase ascii wide
                        $string5 = /\\Program\sFiles\s\(x86\)\\Lansweeper/ nocase ascii wide
                        $string6 = ">Lansweeper Setup<" nocase ascii wide
                        $string7 = ">Lansweeper<" nocase ascii wide
                        $string8 = /https\:\/\/update\.lansweeper\.com\/installation\.aspx/ nocase ascii wide
                        $string9 = /https\:\/\/www\.lansweeper\.com\/installation\.aspx/ nocase ascii wide

    condition:
        any of them
}