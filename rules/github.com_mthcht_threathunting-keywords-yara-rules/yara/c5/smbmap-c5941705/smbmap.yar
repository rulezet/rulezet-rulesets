rule smbmap
{
    meta:
        description = "Detection patterns for the tool 'smbmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-H\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-r\s.{0,1000}C\$\/Users/ nocase ascii wide
                        $string2 = /\s\-\-host\-file\s.{0,1000}\.txt\s\-u\s.{0,1000}\s\-\-prompt\s\-\-admin\s\-\-no\-banner/ nocase ascii wide
                        $string3 = /\/smbmap\.git/ nocase ascii wide
                        $string4 = /\\\\\\\\.{0,1000}\\\\.{0,1000}\\\\Get\-FileLockProcess\.ps1/ nocase ascii wide
                        $string5 = /cmd\s\/c\s.{0,1000}if\sexist\s.{0,1000}\.txt\secho\sImHere/ nocase ascii wide
                        $string6 = "install smbmap" nocase ascii wide
                        $string7 = "install smbmap" nocase ascii wide
                        $string8 = "ShawnDEvans/smbmap" nocase ascii wide
                        $string9 = "smbmap -" nocase ascii wide
                        $string10 = /smbmap\.py\s/ nocase ascii wide
                        $string11 = /smbmap\.smbmap/ nocase ascii wide
                        $string12 = "smbmap-master" nocase ascii wide
                        $string13 = /\-x\s.{0,1000}net\sgroup\s.{0,1000}Domain\sAdmins.{0,1000}\s\/domain/ nocase ascii wide

    condition:
        any of them
}