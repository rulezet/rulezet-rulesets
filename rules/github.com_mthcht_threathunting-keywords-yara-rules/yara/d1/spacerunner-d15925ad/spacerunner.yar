rule SpaceRunner
{
    meta:
        description = "Detection patterns for the tool 'SpaceRunner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpaceRunner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -f Find-AllVulns" nocase ascii wide
                        $string2 = " -f Find-PathDLLHijack" nocase ascii wide
                        $string3 = /\s\-f\sGet\-DomainGroupMember.{0,1000}\s\-a\s.{0,1000}\-Identity\s.{0,1000}admin.{0,1000}\s\-Recurse/ nocase ascii wide
                        $string4 = " -f Invoke-Inveigh" nocase ascii wide
                        $string5 = /\/out\:spacerunner\.exe/ nocase ascii wide
                        $string6 = /\/SpaceRunner\.git/ nocase ascii wide
                        $string7 = /\/target\:exe\sspacerunner\.cs/ nocase ascii wide
                        $string8 = /\[\+\]\sGenerating\sbase64\sencoded\sPowerShell\sscript/ nocase ascii wide
                        $string9 = /\\inveigh\.exe/ nocase ascii wide
                        $string10 = /\\Powerup\.exe/ nocase ascii wide
                        $string11 = /\\Powerview\.exe/ nocase ascii wide
                        $string12 = /\\sherlock\.exe/ nocase ascii wide
                        $string13 = /beacon\.ps1.{0,1000}beacon\.exe/ nocase ascii wide
                        $string14 = "Mr-B0b/SpaceRunner" nocase ascii wide
                        $string15 = /spacerunner\.exe\s\-i\s.{0,1000}\.ps1.{0,1000}\s\-o\s.{0,1000}\.exe/ nocase ascii wide
                        $string16 = /SpaceRunner\-master\.zip/ nocase ascii wide

    condition:
        any of them
}