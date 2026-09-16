rule rule_SafetyDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SafetyDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SafetyDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SafetyDump_offensive_tool_keyword = /\/SafetyDump\.exe/ nocase ascii wide
                        $string2_SafetyDump_offensive_tool_keyword = /\/SafetyDump\.git/ nocase ascii wide
                        $string3_SafetyDump_offensive_tool_keyword = /\\SafetyDump\.csproj/ nocase ascii wide
                        $string4_SafetyDump_offensive_tool_keyword = /\\SafetyDump\.exe/ nocase ascii wide
                        $string5_SafetyDump_offensive_tool_keyword = /\\SafetyDump\.sln/ nocase ascii wide
                        $string6_SafetyDump_offensive_tool_keyword = "738f3dce5ad63a16b2cf8b236d8d374022f121c0990e92adc214a6d03b0dc345" nocase ascii wide
                        $string7_SafetyDump_offensive_tool_keyword = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase ascii wide
                        $string8_SafetyDump_offensive_tool_keyword = "88888dcb2ac77d09b3c68c26f025f1e1ba9db667f3950a79a110896de297e162" nocase ascii wide
                        $string9_SafetyDump_offensive_tool_keyword = "989cb6a23ecba5fb7785a1e23b61b84c12ff45723eb98bb885905768e0a9550a" nocase ascii wide
                        $string10_SafetyDump_offensive_tool_keyword = "namespace SafetyDump" nocase ascii wide
                        $string11_SafetyDump_offensive_tool_keyword = "riskydissonance/SafetyDump" nocase ascii wide
                        $string12_SafetyDump_offensive_tool_keyword = /SafetyDump\.exe\s/ nocase ascii wide

    condition:
        any of them
}