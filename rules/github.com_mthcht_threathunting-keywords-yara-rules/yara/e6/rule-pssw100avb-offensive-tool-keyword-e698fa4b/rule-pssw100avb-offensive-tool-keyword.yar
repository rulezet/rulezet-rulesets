rule rule_PSSW100AVB_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PSSW100AVB' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSSW100AVB"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PSSW100AVB_offensive_tool_keyword = "/PSSW100AVB" nocase ascii wide
                        $string2_PSSW100AVB_offensive_tool_keyword = /AMSI_bypass_20.{0,1000}\.ps1/ nocase ascii wide
                        $string3_PSSW100AVB_offensive_tool_keyword = /LsassDump_20.{0,1000}\.ps1/ nocase ascii wide
                        $string4_PSSW100AVB_offensive_tool_keyword = /ReverseShell_20.{0,1000}\.ps1/ nocase ascii wide

    condition:
        any of them
}