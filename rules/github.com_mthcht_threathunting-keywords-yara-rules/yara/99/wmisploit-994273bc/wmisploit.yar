rule Wmisploit
{
    meta:
        description = "Detection patterns for the tool 'Wmisploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Wmisploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-RemotePath\s.{0,1000}\\Windows\\System32\\SAM\s\-LocalPath\s.{0,1000}\\tmp\\/ nocase ascii wide
                        $string2 = "/wmisploit" nocase ascii wide
                        $string3 = "Enter-WmiShell " nocase ascii wide
                        $string4 = /Enter\-WmiShell\.ps1/ nocase ascii wide
                        $string5 = "Invoke-WmiCommand" nocase ascii wide
                        $string6 = "Invoke-WmiShadowCopy" nocase ascii wide
                        $string7 = /New\-WmiSession\.ps1/ nocase ascii wide
                        $string8 = /WmiSploit\.git/ nocase ascii wide
                        $string9 = "WmiSploit-master/zip" nocase ascii wide

    condition:
        any of them
}