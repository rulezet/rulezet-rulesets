rule rule_EDRPrison_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EDRPrison' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRPrison"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EDRPrison_offensive_tool_keyword = /\/EDRPrison\.git/ nocase ascii wide
                        $string2_EDRPrison_offensive_tool_keyword = /\\EDRPrison\.csproj/ nocase ascii wide
                        $string3_EDRPrison_offensive_tool_keyword = /\\EDRPrison\-main/ nocase ascii wide
                        $string4_EDRPrison_offensive_tool_keyword = "036fedcd8c1d30e41ad0f36aa87f90338b7d1310632c729706d918a34d398eb5" nocase ascii wide
                        $string5_EDRPrison_offensive_tool_keyword = "1cbb36d4cf2b775b3009d1d33ce8a90c8a321cc30b884250639142cea085ac06" nocase ascii wide
                        $string6_EDRPrison_offensive_tool_keyword = "9674DF71-0814-4398-8A77-5A32A8CBE61E" nocase ascii wide
                        $string7_EDRPrison_offensive_tool_keyword = "senzee1984/EDRPrison" nocase ascii wide

    condition:
        any of them
}