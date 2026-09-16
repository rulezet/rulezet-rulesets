rule rule_JunctionFolder_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'JunctionFolder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JunctionFolder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_JunctionFolder_offensive_tool_keyword = /\%APPDATA\%\/Indexing\./ nocase ascii wide
                        $string2_JunctionFolder_offensive_tool_keyword = "/master/JunctionFolder/" nocase ascii wide
                        $string3_JunctionFolder_offensive_tool_keyword = /\\JunctionFolder\.csproj/ nocase ascii wide
                        $string4_JunctionFolder_offensive_tool_keyword = /C\:\\Users\\.{0,1000}\\AppData\\Roaming\\Indexing\./ nocase ascii wide
                        $string5_JunctionFolder_offensive_tool_keyword = /JunctionFolder\.exe/ nocase ascii wide

    condition:
        any of them
}