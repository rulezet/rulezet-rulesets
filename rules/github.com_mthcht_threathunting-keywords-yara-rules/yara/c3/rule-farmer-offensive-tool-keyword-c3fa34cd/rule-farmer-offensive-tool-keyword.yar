rule rule_Farmer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Farmer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Farmer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Farmer_offensive_tool_keyword = /\/Farmer\.git/ nocase ascii wide
                        $string2_Farmer_offensive_tool_keyword = /\\Fertliser\.exe/ nocase ascii wide
                        $string3_Farmer_offensive_tool_keyword = /\\Fertliser\.pdb/ nocase ascii wide
                        $string4_Farmer_offensive_tool_keyword = /c\:\\windows\\temp\\test\.tmp\sfarmer/ nocase ascii wide
                        $string5_Farmer_offensive_tool_keyword = /crop\.exe\s\\\\.{0,1000}\\.{0,1000}\.lnk\s\\\\.{0,1000}\\harvest\s\\\\.{0,1000}\\harvest/ nocase ascii wide
                        $string6_Farmer_offensive_tool_keyword = /farmer\.exe\s.{0,1000}\\windows\\temp/ nocase ascii wide
                        $string7_Farmer_offensive_tool_keyword = /farmer\.exe\s8888\s60/ nocase ascii wide
                        $string8_Farmer_offensive_tool_keyword = /Farmer\\Farmer\.csproj/ nocase ascii wide
                        $string9_Farmer_offensive_tool_keyword = /Farmer\-main\.zip/ nocase ascii wide
                        $string10_Farmer_offensive_tool_keyword = /Fertiliser\.exe\s\\\\/ nocase ascii wide
                        $string11_Farmer_offensive_tool_keyword = /harvestcrop\.exe\s.{0,1000}\s/ nocase ascii wide
                        $string12_Farmer_offensive_tool_keyword = "mdsecactivebreach/Farmer" nocase ascii wide

    condition:
        any of them
}