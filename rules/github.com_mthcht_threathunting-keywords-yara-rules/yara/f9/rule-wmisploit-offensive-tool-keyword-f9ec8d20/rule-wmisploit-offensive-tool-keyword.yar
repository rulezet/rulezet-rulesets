rule rule_Wmisploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Wmisploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Wmisploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Wmisploit_offensive_tool_keyword = /\s\-RemotePath\s.{0,1000}\\Windows\\System32\\SAM\s\-LocalPath\s.{0,1000}\\tmp\\/ nocase ascii wide
                        $string2_Wmisploit_offensive_tool_keyword = "/wmisploit" nocase ascii wide
                        $string3_Wmisploit_offensive_tool_keyword = "Enter-WmiShell " nocase ascii wide
                        $string4_Wmisploit_offensive_tool_keyword = /Enter\-WmiShell\.ps1/ nocase ascii wide
                        $string5_Wmisploit_offensive_tool_keyword = "Invoke-WmiCommand" nocase ascii wide
                        $string6_Wmisploit_offensive_tool_keyword = "Invoke-WmiShadowCopy" nocase ascii wide
                        $string7_Wmisploit_offensive_tool_keyword = /New\-WmiSession\.ps1/ nocase ascii wide
                        $string8_Wmisploit_offensive_tool_keyword = /WmiSploit\.git/ nocase ascii wide
                        $string9_Wmisploit_offensive_tool_keyword = "WmiSploit-master/zip" nocase ascii wide

    condition:
        any of them
}