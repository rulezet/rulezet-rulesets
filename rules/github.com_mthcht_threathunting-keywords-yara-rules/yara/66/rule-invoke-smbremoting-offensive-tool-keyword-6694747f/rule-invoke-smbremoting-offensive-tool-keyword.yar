rule rule_Invoke_SMBRemoting_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SMBRemoting' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SMBRemoting"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_SMBRemoting_offensive_tool_keyword = /\s\-PipeName\s.{0,1000}\s\-ServiceName\s.{0,1000}\s\-Command\swhoami/ nocase ascii wide
                        $string2_Invoke_SMBRemoting_offensive_tool_keyword = /\/Invoke\-SMBRemoting\.git/ nocase ascii wide
                        $string3_Invoke_SMBRemoting_offensive_tool_keyword = "Enter-SMBSession -ComputerName " nocase ascii wide
                        $string4_Invoke_SMBRemoting_offensive_tool_keyword = /Enter\-SMBSession.{0,1000}\s\-PipeName\s.{0,1000}\s\-ServiceName\s/ nocase ascii wide
                        $string5_Invoke_SMBRemoting_offensive_tool_keyword = /Invoke\-SMBRemoting\.ps1/ nocase ascii wide
                        $string6_Invoke_SMBRemoting_offensive_tool_keyword = "Invoke-SMBRemoting-main" nocase ascii wide
                        $string7_Invoke_SMBRemoting_offensive_tool_keyword = "Leo4j/Invoke-SMBRemoting" nocase ascii wide

    condition:
        any of them
}