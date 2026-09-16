rule rule_SpaceRunner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SpaceRunner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpaceRunner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SpaceRunner_offensive_tool_keyword = " -f Find-AllVulns" nocase ascii wide
                        $string2_SpaceRunner_offensive_tool_keyword = " -f Find-PathDLLHijack" nocase ascii wide
                        $string3_SpaceRunner_offensive_tool_keyword = /\s\-f\sGet\-DomainGroupMember.{0,1000}\s\-a\s.{0,1000}\-Identity\s.{0,1000}admin.{0,1000}\s\-Recurse/ nocase ascii wide
                        $string4_SpaceRunner_offensive_tool_keyword = " -f Invoke-Inveigh" nocase ascii wide
                        $string5_SpaceRunner_offensive_tool_keyword = /\/out\:spacerunner\.exe/ nocase ascii wide
                        $string6_SpaceRunner_offensive_tool_keyword = /\/SpaceRunner\.git/ nocase ascii wide
                        $string7_SpaceRunner_offensive_tool_keyword = /\/target\:exe\sspacerunner\.cs/ nocase ascii wide
                        $string8_SpaceRunner_offensive_tool_keyword = /\[\+\]\sGenerating\sbase64\sencoded\sPowerShell\sscript/ nocase ascii wide
                        $string9_SpaceRunner_offensive_tool_keyword = /\\inveigh\.exe/ nocase ascii wide
                        $string10_SpaceRunner_offensive_tool_keyword = /\\Powerup\.exe/ nocase ascii wide
                        $string11_SpaceRunner_offensive_tool_keyword = /\\Powerview\.exe/ nocase ascii wide
                        $string12_SpaceRunner_offensive_tool_keyword = /\\sherlock\.exe/ nocase ascii wide
                        $string13_SpaceRunner_offensive_tool_keyword = /beacon\.ps1.{0,1000}beacon\.exe/ nocase ascii wide
                        $string14_SpaceRunner_offensive_tool_keyword = "Mr-B0b/SpaceRunner" nocase ascii wide
                        $string15_SpaceRunner_offensive_tool_keyword = /spacerunner\.exe\s\-i\s.{0,1000}\.ps1.{0,1000}\s\-o\s.{0,1000}\.exe/ nocase ascii wide
                        $string16_SpaceRunner_offensive_tool_keyword = /SpaceRunner\-master\.zip/ nocase ascii wide

    condition:
        any of them
}