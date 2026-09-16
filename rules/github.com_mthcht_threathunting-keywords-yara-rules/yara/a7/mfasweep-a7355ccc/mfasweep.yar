rule MFASweep
{
    meta:
        description = "Detection patterns for the tool 'MFASweep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MFASweep"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-Username\s.{0,1000}\s\-Password\s.{0,1000}\s\-Recon\s\-IncludeADFS/ nocase ascii wide
                        $string2 = /\/MFASweep\.git/ nocase ascii wide
                        $string3 = "dafthack/MFASweep" nocase ascii wide
                        $string4 = "Invoke-MFASweep" nocase ascii wide
                        $string5 = /MFASweep\.ps1/ nocase ascii wide

    condition:
        any of them
}