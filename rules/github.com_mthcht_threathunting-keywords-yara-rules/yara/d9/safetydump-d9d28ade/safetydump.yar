rule SafetyDump
{
    meta:
        description = "Detection patterns for the tool 'SafetyDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SafetyDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SafetyDump\.exe/ nocase ascii wide
                        $string2 = /\/SafetyDump\.git/ nocase ascii wide
                        $string3 = /\\SafetyDump\.csproj/ nocase ascii wide
                        $string4 = /\\SafetyDump\.exe/ nocase ascii wide
                        $string5 = /\\SafetyDump\.sln/ nocase ascii wide
                        $string6 = "738f3dce5ad63a16b2cf8b236d8d374022f121c0990e92adc214a6d03b0dc345" nocase ascii wide
                        $string7 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase ascii wide
                        $string8 = "88888dcb2ac77d09b3c68c26f025f1e1ba9db667f3950a79a110896de297e162" nocase ascii wide
                        $string9 = "989cb6a23ecba5fb7785a1e23b61b84c12ff45723eb98bb885905768e0a9550a" nocase ascii wide
                        $string10 = "namespace SafetyDump" nocase ascii wide
                        $string11 = "riskydissonance/SafetyDump" nocase ascii wide
                        $string12 = /SafetyDump\.exe\s/ nocase ascii wide

    condition:
        any of them
}