rule Adcheck
{
    meta:
        description = "Detection patterns for the tool 'Adcheck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adcheck"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sADcheck\.py/ nocase ascii wide
                        $string2 = " --bloodhound-file " nocase ascii wide
                        $string3 = /\sGPOBrowser\.py/ nocase ascii wide
                        $string4 = /\sSmallSecretsDump\.py/ nocase ascii wide
                        $string5 = /\/ADcheck\.git/ nocase ascii wide
                        $string6 = /\/ADcheck\.py/ nocase ascii wide
                        $string7 = /\/GPOBrowser\.py/ nocase ascii wide
                        $string8 = /\/SmallSecretsDump\.py/ nocase ascii wide
                        $string9 = /\\ADcheck\.py/ nocase ascii wide
                        $string10 = /\\ADcheck\\Scripts\\activate/ nocase ascii wide
                        $string11 = /\\ADcheck\-main/ nocase ascii wide
                        $string12 = /\\GPOBrowser\.py/ nocase ascii wide
                        $string13 = /\\SmallSecretsDump\.py/ nocase ascii wide
                        $string14 = "29169875afabc27c2b4184d94689aae0955a6d8a7d11788fa3337efd807077ba" nocase ascii wide
                        $string15 = /admin_can_be_delegated\(self\)/ nocase ascii wide
                        $string16 = /asreproast\(/ nocase ascii wide
                        $string17 = "bdc2c691a61df0926160a728c8419244fa2a1523bf3a3c61a353afa78d80cbfe" nocase ascii wide
                        $string18 = "CobblePot59/ADcheck" nocase ascii wide
                        $string19 = "f4a493d7a8c194fa599d23d6302a5bd7092fe01a60d7803688546b8cb68d8bf4" nocase ascii wide
                        $string20 = /kerberoast\(self\)/ nocase ascii wide
                        $string21 = /krbtgt_password_age\(self\)/ nocase ascii wide
                        $string22 = "python -m venv ADcheck" nocase ascii wide

    condition:
        any of them
}