rule rule_powerview_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'powerview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powerview"
        rule_category = "signature_keyword"

    strings:
                        $string1_powerview_signature_keyword = "ATK/PowSploit-A" nocase ascii wide
                        $string2_powerview_signature_keyword = /HackTool\.PowerShell\.PowerSploit/ nocase ascii wide
                        $string3_powerview_signature_keyword = /HackTool\.PowerView/ nocase ascii wide
                        $string4_powerview_signature_keyword = /HackTool\.PS1\.PowerSploit/ nocase ascii wide
                        $string5_powerview_signature_keyword = "HackTool:PowerShell/PowerView" nocase ascii wide
                        $string6_powerview_signature_keyword = "HTool-EmpireAgent" nocase ascii wide
                        $string7_powerview_signature_keyword = /Trojan\.HackTool\.PowerSploit/ nocase ascii wide

    condition:
        any of them
}