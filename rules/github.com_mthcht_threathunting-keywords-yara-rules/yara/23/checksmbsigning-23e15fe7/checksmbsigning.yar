rule CheckSMBSigning
{
    meta:
        description = "Detection patterns for the tool 'CheckSMBSigning' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheckSMBSigning"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sCheckSMBSigning\.ps1/ nocase ascii wide
                        $string2 = /\sGet\-SMBSigning\.ps1/ nocase ascii wide
                        $string3 = /\/CheckSMBSigning\.git/ nocase ascii wide
                        $string4 = /\/CheckSMBSigning\.ps1/ nocase ascii wide
                        $string5 = /\/Get\-SMBSigning\.ps1/ nocase ascii wide
                        $string6 = /\\CheckSMBSigning\.ps1/ nocase ascii wide
                        $string7 = /\\Get\-SMBSigning\.ps1/ nocase ascii wide
                        $string8 = /\\SMBSigningNotRequired\.txt/ nocase ascii wide
                        $string9 = "2b38b8acc2d37042c0f5c2a8932f59ce8d5556103a54f2665a648476d214cc45" nocase ascii wide
                        $string10 = "CheckSMBSigning -Targets " nocase ascii wide
                        $string11 = "Get-SMBSigning -DelayJitter " nocase ascii wide
                        $string12 = "Leo4j/CheckSMBSigning" nocase ascii wide

    condition:
        any of them
}