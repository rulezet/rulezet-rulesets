rule Invoke_SMBRemoting
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SMBRemoting' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SMBRemoting"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-PipeName\s.{0,1000}\s\-ServiceName\s.{0,1000}\s\-Command\swhoami/ nocase ascii wide
                        $string2 = /\/Invoke\-SMBRemoting\.git/ nocase ascii wide
                        $string3 = "Enter-SMBSession -ComputerName " nocase ascii wide
                        $string4 = /Enter\-SMBSession.{0,1000}\s\-PipeName\s.{0,1000}\s\-ServiceName\s/ nocase ascii wide
                        $string5 = /Invoke\-SMBRemoting\.ps1/ nocase ascii wide
                        $string6 = "Invoke-SMBRemoting-main" nocase ascii wide
                        $string7 = "Leo4j/Invoke-SMBRemoting" nocase ascii wide

    condition:
        any of them
}