rule rule_CheckSMBSigning_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CheckSMBSigning' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheckSMBSigning"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CheckSMBSigning_offensive_tool_keyword = /\sCheckSMBSigning\.ps1/ nocase ascii wide
                        $string2_CheckSMBSigning_offensive_tool_keyword = /\sGet\-SMBSigning\.ps1/ nocase ascii wide
                        $string3_CheckSMBSigning_offensive_tool_keyword = /\/CheckSMBSigning\.git/ nocase ascii wide
                        $string4_CheckSMBSigning_offensive_tool_keyword = /\/CheckSMBSigning\.ps1/ nocase ascii wide
                        $string5_CheckSMBSigning_offensive_tool_keyword = /\/Get\-SMBSigning\.ps1/ nocase ascii wide
                        $string6_CheckSMBSigning_offensive_tool_keyword = /\\CheckSMBSigning\.ps1/ nocase ascii wide
                        $string7_CheckSMBSigning_offensive_tool_keyword = /\\Get\-SMBSigning\.ps1/ nocase ascii wide
                        $string8_CheckSMBSigning_offensive_tool_keyword = /\\SMBSigningNotRequired\.txt/ nocase ascii wide
                        $string9_CheckSMBSigning_offensive_tool_keyword = "2b38b8acc2d37042c0f5c2a8932f59ce8d5556103a54f2665a648476d214cc45" nocase ascii wide
                        $string10_CheckSMBSigning_offensive_tool_keyword = "CheckSMBSigning -Targets " nocase ascii wide
                        $string11_CheckSMBSigning_offensive_tool_keyword = "Get-SMBSigning -DelayJitter " nocase ascii wide
                        $string12_CheckSMBSigning_offensive_tool_keyword = "Leo4j/CheckSMBSigning" nocase ascii wide

    condition:
        any of them
}