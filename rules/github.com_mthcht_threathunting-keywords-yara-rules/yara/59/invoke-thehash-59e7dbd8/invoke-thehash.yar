rule Invoke_TheHash
{
    meta:
        description = "Detection patterns for the tool 'Invoke-TheHash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-TheHash"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-Type\sSMBClient\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
                        $string2 = /\s\-Type\sSMBEnum\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
                        $string3 = /\s\-Type\sSMBExec\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
                        $string4 = " -Type WMIExec " nocase ascii wide
                        $string5 = /\s\-Type\sWMIExec\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
                        $string6 = /\[\-\]\s.{0,1000}\sdoes\snot\shave\sService\sControl\sManager\swrite\sprivilege\son\s/ nocase ascii wide
                        $string7 = /\[\-\]\sInveigh\sRelay\ssession\s/ nocase ascii wide
                        $string8 = /Invoke\-SMBClient\.ps1/ nocase ascii wide
                        $string9 = "Invoke-SMBEnum" nocase ascii wide
                        $string10 = "Invoke-SMBExec" nocase ascii wide
                        $string11 = "Invoke-TheHash" nocase ascii wide
                        $string12 = /Invoke\-TheHash\.ps1/ nocase ascii wide
                        $string13 = /Invoke\-TheHash\.psd1/ nocase ascii wide
                        $string14 = /Invoke\-TheHash\.psm1/ nocase ascii wide
                        $string15 = "Invoke-WMIExec " nocase ascii wide
                        $string16 = /Invoke\-WMIExec\.ps1/ nocase ascii wide
                        $string17 = "New-PacketSMB2IoctlRequest" nocase ascii wide

    condition:
        any of them
}