rule adrecon
{
    meta:
        description = "Detection patterns for the tool 'adrecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adrecon"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sADRecon\.ps1/ nocase ascii wide
                        $string2 = /\$base64adrecon/ nocase ascii wide
                        $string3 = /\/ADRecon\.git/ nocase ascii wide
                        $string4 = /\/ADRecon\.ps1/ nocase ascii wide
                        $string5 = /\[\-\]\sKerberoast/ nocase ascii wide
                        $string6 = /\[Get\-ADRRevertToSelf\]\sToken\simpersonation\ssuccessfully\sreverted/ nocase ascii wide
                        $string7 = /\[Get\-ADR\-UserImpersonation\]\sAlternate\scredentials\ssuccessfully\simpersonated/ nocase ascii wide
                        $string8 = /\\ADRecon\.ps1/ nocase ascii wide
                        $string9 = /\\ADRecon\-master/ nocase ascii wide
                        $string10 = /\\ADRecon\-Report\.xlsx/ nocase ascii wide
                        $string11 = /\\BitLockerRecoveryKeys\.csv/ nocase ascii wide
                        $string12 = /\\DefaultPasswordPolicy\.csv/ nocase ascii wide
                        $string13 = "309a6b123ebdbb92766addeb8326311b86c26a21eb5cad30c8cde6c237019046" nocase ascii wide
                        $string14 = /ADRecon\s.{0,1000}\sby\sPrashant\sMahajan\s\(\@prashant3535\)/ nocase ascii wide
                        $string15 = "ADRecon -OutputDir " nocase ascii wide
                        $string16 = /ADRecon\.ps1/ nocase ascii wide
                        $string17 = "adrecon/ADRecon" nocase ascii wide
                        $string18 = /ADRecon\-Console\-Log\.txt/ nocase ascii wide
                        $string19 = /ADRecon\-master\.zip/ nocase ascii wide
                        $string20 = "ADRecon-Report-" nocase ascii wide
                        $string21 = /\-ADRecon\-Report\.xlsx/ nocase ascii wide
                        $string22 = /Get\-LAPSPasswords\.ps1/ nocase ascii wide
                        $string23 = "Invoke-ADRecon" nocase ascii wide
                        $string24 = "Invoke-UserImpersonation -Credential " nocase ascii wide

    condition:
        any of them
}