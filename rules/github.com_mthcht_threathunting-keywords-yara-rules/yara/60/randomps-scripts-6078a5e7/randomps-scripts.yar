rule RandomPS_Scripts
{
    meta:
        description = "Detection patterns for the tool 'RandomPS-Scripts' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RandomPS-Scripts"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\?function\sInvoke\-CylanceDisarm/ nocase ascii wide
                        $string2 = /DisableCylance\.ps1/ nocase ascii wide
                        $string3 = /Invoke\-CylanceDisarm\s\-ProcessID\s.{0,1000}\s\-DisableMemDef/ nocase ascii wide
                        $string4 = "Invoke-WindowsEnum" nocase ascii wide
                        $string5 = /Invoke\-WmicDriveBy\./ nocase ascii wide
                        $string6 = "Set-WMIBackdoor -URL " nocase ascii wide
                        $string7 = /WMIBackdoor\.ps1/ nocase ascii wide

    condition:
        any of them
}