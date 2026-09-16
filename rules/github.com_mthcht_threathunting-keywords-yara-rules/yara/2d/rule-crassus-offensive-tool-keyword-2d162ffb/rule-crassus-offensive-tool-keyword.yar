rule rule_Crassus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Crassus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Crassus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Crassus_offensive_tool_keyword = /\/Crassus\.git/ nocase ascii wide
                        $string2_Crassus_offensive_tool_keyword = "/Crassus-main" nocase ascii wide
                        $string3_Crassus_offensive_tool_keyword = /\\Crassus\-main/ nocase ascii wide
                        $string4_Crassus_offensive_tool_keyword = "7E9729AA-4CF2-4D0A-8183-7FB7CE7A5B1A" nocase ascii wide
                        $string5_Crassus_offensive_tool_keyword = /Crassus\.csproj/ nocase ascii wide
                        $string6_Crassus_offensive_tool_keyword = /Crassus\.exe/ nocase ascii wide
                        $string7_Crassus_offensive_tool_keyword = /Crassus\.sln/ nocase ascii wide
                        $string8_Crassus_offensive_tool_keyword = "vu-ls/Crassus" nocase ascii wide

    condition:
        any of them
}