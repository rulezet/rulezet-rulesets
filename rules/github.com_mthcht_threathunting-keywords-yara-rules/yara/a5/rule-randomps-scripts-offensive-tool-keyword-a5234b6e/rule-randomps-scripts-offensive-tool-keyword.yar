rule rule_RandomPS_Scripts_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RandomPS-Scripts' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RandomPS-Scripts"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RandomPS_Scripts_offensive_tool_keyword = /\?function\sInvoke\-CylanceDisarm/ nocase ascii wide
                        $string2_RandomPS_Scripts_offensive_tool_keyword = /DisableCylance\.ps1/ nocase ascii wide
                        $string3_RandomPS_Scripts_offensive_tool_keyword = /Invoke\-CylanceDisarm\s\-ProcessID\s.{0,1000}\s\-DisableMemDef/ nocase ascii wide
                        $string4_RandomPS_Scripts_offensive_tool_keyword = "Invoke-WindowsEnum" nocase ascii wide
                        $string5_RandomPS_Scripts_offensive_tool_keyword = /Invoke\-WmicDriveBy\./ nocase ascii wide
                        $string6_RandomPS_Scripts_offensive_tool_keyword = "Set-WMIBackdoor -URL " nocase ascii wide
                        $string7_RandomPS_Scripts_offensive_tool_keyword = /WMIBackdoor\.ps1/ nocase ascii wide

    condition:
        any of them
}