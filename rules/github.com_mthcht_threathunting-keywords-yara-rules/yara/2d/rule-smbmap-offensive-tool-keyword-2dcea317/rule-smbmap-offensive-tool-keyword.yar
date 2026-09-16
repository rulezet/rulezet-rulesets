rule rule_smbmap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'smbmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_smbmap_offensive_tool_keyword = /\s\-H\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-r\s.{0,1000}C\$\/Users/ nocase ascii wide
                        $string2_smbmap_offensive_tool_keyword = /\s\-\-host\-file\s.{0,1000}\.txt\s\-u\s.{0,1000}\s\-\-prompt\s\-\-admin\s\-\-no\-banner/ nocase ascii wide
                        $string3_smbmap_offensive_tool_keyword = /\/smbmap\.git/ nocase ascii wide
                        $string4_smbmap_offensive_tool_keyword = /\\\\\\\\.{0,1000}\\\\.{0,1000}\\\\Get\-FileLockProcess\.ps1/ nocase ascii wide
                        $string5_smbmap_offensive_tool_keyword = /cmd\s\/c\s.{0,1000}if\sexist\s.{0,1000}\.txt\secho\sImHere/ nocase ascii wide
                        $string6_smbmap_offensive_tool_keyword = "install smbmap" nocase ascii wide
                        $string7_smbmap_offensive_tool_keyword = "install smbmap" nocase ascii wide
                        $string8_smbmap_offensive_tool_keyword = "ShawnDEvans/smbmap" nocase ascii wide
                        $string9_smbmap_offensive_tool_keyword = "smbmap -" nocase ascii wide
                        $string10_smbmap_offensive_tool_keyword = /smbmap\.py\s/ nocase ascii wide
                        $string11_smbmap_offensive_tool_keyword = /smbmap\.smbmap/ nocase ascii wide
                        $string12_smbmap_offensive_tool_keyword = "smbmap-master" nocase ascii wide
                        $string13_smbmap_offensive_tool_keyword = /\-x\s.{0,1000}net\sgroup\s.{0,1000}Domain\sAdmins.{0,1000}\s\/domain/ nocase ascii wide

    condition:
        any of them
}