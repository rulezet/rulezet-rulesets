rule rule_adrecon_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adrecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adrecon"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_adrecon_greyware_tool_keyword = /\sADRecon\.ps1/ nocase ascii wide
                        $string2_adrecon_greyware_tool_keyword = /\$base64adrecon/ nocase ascii wide
                        $string3_adrecon_greyware_tool_keyword = /\/ADRecon\.git/ nocase ascii wide
                        $string4_adrecon_greyware_tool_keyword = /\/ADRecon\.ps1/ nocase ascii wide
                        $string5_adrecon_greyware_tool_keyword = /\[\-\]\sKerberoast/ nocase ascii wide
                        $string6_adrecon_greyware_tool_keyword = /\[Get\-ADRRevertToSelf\]\sToken\simpersonation\ssuccessfully\sreverted/ nocase ascii wide
                        $string7_adrecon_greyware_tool_keyword = /\[Get\-ADR\-UserImpersonation\]\sAlternate\scredentials\ssuccessfully\simpersonated/ nocase ascii wide
                        $string8_adrecon_greyware_tool_keyword = /\\ADRecon\.ps1/ nocase ascii wide
                        $string9_adrecon_greyware_tool_keyword = /\\ADRecon\-master/ nocase ascii wide
                        $string10_adrecon_greyware_tool_keyword = /\\ADRecon\-Report\.xlsx/ nocase ascii wide
                        $string11_adrecon_greyware_tool_keyword = /\\BitLockerRecoveryKeys\.csv/ nocase ascii wide
                        $string12_adrecon_greyware_tool_keyword = /\\DefaultPasswordPolicy\.csv/ nocase ascii wide
                        $string13_adrecon_greyware_tool_keyword = "309a6b123ebdbb92766addeb8326311b86c26a21eb5cad30c8cde6c237019046" nocase ascii wide
                        $string14_adrecon_greyware_tool_keyword = /ADRecon\s.{0,1000}\sby\sPrashant\sMahajan\s\(\@prashant3535\)/ nocase ascii wide
                        $string15_adrecon_greyware_tool_keyword = "ADRecon -OutputDir " nocase ascii wide
                        $string16_adrecon_greyware_tool_keyword = /ADRecon\.ps1/ nocase ascii wide
                        $string17_adrecon_greyware_tool_keyword = "adrecon/ADRecon" nocase ascii wide
                        $string18_adrecon_greyware_tool_keyword = /ADRecon\-Console\-Log\.txt/ nocase ascii wide
                        $string19_adrecon_greyware_tool_keyword = /ADRecon\-master\.zip/ nocase ascii wide
                        $string20_adrecon_greyware_tool_keyword = "ADRecon-Report-" nocase ascii wide
                        $string21_adrecon_greyware_tool_keyword = /\-ADRecon\-Report\.xlsx/ nocase ascii wide
                        $string22_adrecon_greyware_tool_keyword = /Get\-LAPSPasswords\.ps1/ nocase ascii wide
                        $string23_adrecon_greyware_tool_keyword = "Invoke-ADRecon" nocase ascii wide
                        $string24_adrecon_greyware_tool_keyword = "Invoke-UserImpersonation -Credential " nocase ascii wide

    condition:
        any of them
}