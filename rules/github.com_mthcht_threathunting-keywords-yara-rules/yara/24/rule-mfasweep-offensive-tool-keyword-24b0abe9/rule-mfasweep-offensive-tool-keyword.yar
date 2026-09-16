rule rule_MFASweep_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MFASweep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MFASweep"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MFASweep_offensive_tool_keyword = /\s\-Username\s.{0,1000}\s\-Password\s.{0,1000}\s\-Recon\s\-IncludeADFS/ nocase ascii wide
                        $string2_MFASweep_offensive_tool_keyword = /\/MFASweep\.git/ nocase ascii wide
                        $string3_MFASweep_offensive_tool_keyword = "dafthack/MFASweep" nocase ascii wide
                        $string4_MFASweep_offensive_tool_keyword = "Invoke-MFASweep" nocase ascii wide
                        $string5_MFASweep_offensive_tool_keyword = /MFASweep\.ps1/ nocase ascii wide

    condition:
        any of them
}