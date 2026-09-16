rule rule_Invoke_TheHash_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-TheHash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-TheHash"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_TheHash_offensive_tool_keyword = /\s\-Type\sSMBClient\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
                        $string2_Invoke_TheHash_offensive_tool_keyword = /\s\-Type\sSMBEnum\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
                        $string3_Invoke_TheHash_offensive_tool_keyword = /\s\-Type\sSMBExec\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
                        $string4_Invoke_TheHash_offensive_tool_keyword = " -Type WMIExec " nocase ascii wide
                        $string5_Invoke_TheHash_offensive_tool_keyword = /\s\-Type\sWMIExec\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
                        $string6_Invoke_TheHash_offensive_tool_keyword = /\[\-\]\s.{0,1000}\sdoes\snot\shave\sService\sControl\sManager\swrite\sprivilege\son\s/ nocase ascii wide
                        $string7_Invoke_TheHash_offensive_tool_keyword = /\[\-\]\sInveigh\sRelay\ssession\s/ nocase ascii wide
                        $string8_Invoke_TheHash_offensive_tool_keyword = /Invoke\-SMBClient\.ps1/ nocase ascii wide
                        $string9_Invoke_TheHash_offensive_tool_keyword = "Invoke-SMBEnum" nocase ascii wide
                        $string10_Invoke_TheHash_offensive_tool_keyword = "Invoke-SMBExec" nocase ascii wide
                        $string11_Invoke_TheHash_offensive_tool_keyword = "Invoke-TheHash" nocase ascii wide
                        $string12_Invoke_TheHash_offensive_tool_keyword = /Invoke\-TheHash\.ps1/ nocase ascii wide
                        $string13_Invoke_TheHash_offensive_tool_keyword = /Invoke\-TheHash\.psd1/ nocase ascii wide
                        $string14_Invoke_TheHash_offensive_tool_keyword = /Invoke\-TheHash\.psm1/ nocase ascii wide
                        $string15_Invoke_TheHash_offensive_tool_keyword = "Invoke-WMIExec " nocase ascii wide
                        $string16_Invoke_TheHash_offensive_tool_keyword = /Invoke\-WMIExec\.ps1/ nocase ascii wide
                        $string17_Invoke_TheHash_offensive_tool_keyword = "New-PacketSMB2IoctlRequest" nocase ascii wide

    condition:
        any of them
}