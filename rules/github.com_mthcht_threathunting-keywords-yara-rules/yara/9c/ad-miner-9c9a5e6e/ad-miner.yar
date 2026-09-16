rule AD_Miner
{
    meta:
        description = "Detection patterns for the tool 'AD_Miner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AD_Miner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AD_Miner\.git/ nocase ascii wide
                        $string2 = /\\AD_Miner\-/ nocase ascii wide
                        $string3 = /ad_miner\.sources\.modules\./ nocase ascii wide
                        $string4 = "AD_Miner-main" nocase ascii wide
                        $string5 = "AD-miner -" nocase ascii wide
                        $string6 = /https\:\/\/discord\.com\/invite\/5Hpj4Gs5SS/ nocase ascii wide
                        $string7 = "Mazars-Tech/AD_Miner" nocase ascii wide

    condition:
        any of them
}