rule rule_Adcheck_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Adcheck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adcheck"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Adcheck_offensive_tool_keyword = /\sADcheck\.py/ nocase ascii wide
                        $string2_Adcheck_offensive_tool_keyword = " --bloodhound-file " nocase ascii wide
                        $string3_Adcheck_offensive_tool_keyword = /\sGPOBrowser\.py/ nocase ascii wide
                        $string4_Adcheck_offensive_tool_keyword = /\sSmallSecretsDump\.py/ nocase ascii wide
                        $string5_Adcheck_offensive_tool_keyword = /\/ADcheck\.git/ nocase ascii wide
                        $string6_Adcheck_offensive_tool_keyword = /\/ADcheck\.py/ nocase ascii wide
                        $string7_Adcheck_offensive_tool_keyword = /\/GPOBrowser\.py/ nocase ascii wide
                        $string8_Adcheck_offensive_tool_keyword = /\/SmallSecretsDump\.py/ nocase ascii wide
                        $string9_Adcheck_offensive_tool_keyword = /\\ADcheck\.py/ nocase ascii wide
                        $string10_Adcheck_offensive_tool_keyword = /\\ADcheck\\Scripts\\activate/ nocase ascii wide
                        $string11_Adcheck_offensive_tool_keyword = /\\ADcheck\-main/ nocase ascii wide
                        $string12_Adcheck_offensive_tool_keyword = /\\GPOBrowser\.py/ nocase ascii wide
                        $string13_Adcheck_offensive_tool_keyword = /\\SmallSecretsDump\.py/ nocase ascii wide
                        $string14_Adcheck_offensive_tool_keyword = "29169875afabc27c2b4184d94689aae0955a6d8a7d11788fa3337efd807077ba" nocase ascii wide
                        $string15_Adcheck_offensive_tool_keyword = /admin_can_be_delegated\(self\)/ nocase ascii wide
                        $string16_Adcheck_offensive_tool_keyword = /asreproast\(/ nocase ascii wide
                        $string17_Adcheck_offensive_tool_keyword = "bdc2c691a61df0926160a728c8419244fa2a1523bf3a3c61a353afa78d80cbfe" nocase ascii wide
                        $string18_Adcheck_offensive_tool_keyword = "CobblePot59/ADcheck" nocase ascii wide
                        $string19_Adcheck_offensive_tool_keyword = "f4a493d7a8c194fa599d23d6302a5bd7092fe01a60d7803688546b8cb68d8bf4" nocase ascii wide
                        $string20_Adcheck_offensive_tool_keyword = /kerberoast\(self\)/ nocase ascii wide
                        $string21_Adcheck_offensive_tool_keyword = /krbtgt_password_age\(self\)/ nocase ascii wide
                        $string22_Adcheck_offensive_tool_keyword = "python -m venv ADcheck" nocase ascii wide

    condition:
        any of them
}