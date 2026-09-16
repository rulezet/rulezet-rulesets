rule LAPSToolkit
{
    meta:
        description = "Detection patterns for the tool 'LAPSToolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSToolkit"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.PS1\.PowerSploit/ nocase ascii wide
                        $string2 = "HTool-EmpireAgent" nocase ascii wide

    condition:
        any of them
}