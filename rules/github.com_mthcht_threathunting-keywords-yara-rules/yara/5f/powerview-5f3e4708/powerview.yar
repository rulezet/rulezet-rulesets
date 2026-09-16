rule powerview
{
    meta:
        description = "Detection patterns for the tool 'powerview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powerview"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ATK/PowSploit-A" nocase ascii wide
                        $string2 = /HackTool\.PowerShell\.PowerSploit/ nocase ascii wide
                        $string3 = /HackTool\.PowerView/ nocase ascii wide
                        $string4 = /HackTool\.PS1\.PowerSploit/ nocase ascii wide
                        $string5 = "HackTool:PowerShell/PowerView" nocase ascii wide
                        $string6 = "HTool-EmpireAgent" nocase ascii wide
                        $string7 = /Trojan\.HackTool\.PowerSploit/ nocase ascii wide

    condition:
        any of them
}