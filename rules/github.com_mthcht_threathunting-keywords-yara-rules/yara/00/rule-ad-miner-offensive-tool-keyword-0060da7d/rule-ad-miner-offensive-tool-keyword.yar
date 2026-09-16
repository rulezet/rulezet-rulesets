rule rule_AD_Miner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AD_Miner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AD_Miner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AD_Miner_offensive_tool_keyword = /\/AD_Miner\.git/ nocase ascii wide
                        $string2_AD_Miner_offensive_tool_keyword = /\\AD_Miner\-/ nocase ascii wide
                        $string3_AD_Miner_offensive_tool_keyword = /ad_miner\.sources\.modules\./ nocase ascii wide
                        $string4_AD_Miner_offensive_tool_keyword = "AD_Miner-main" nocase ascii wide
                        $string5_AD_Miner_offensive_tool_keyword = "AD-miner -" nocase ascii wide
                        $string6_AD_Miner_offensive_tool_keyword = /https\:\/\/discord\.com\/invite\/5Hpj4Gs5SS/ nocase ascii wide
                        $string7_AD_Miner_offensive_tool_keyword = "Mazars-Tech/AD_Miner" nocase ascii wide

    condition:
        any of them
}