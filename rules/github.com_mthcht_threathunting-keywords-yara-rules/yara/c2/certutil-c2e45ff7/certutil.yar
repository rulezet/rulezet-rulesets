rule certutil
{
    meta:
        description = "Detection patterns for the tool 'certutil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "certutil"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /certutil\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.exe/ nocase ascii wide
                        $string2 = /certutil\.exe\s\-urlcache\s\-split\s\-f\s.{0,1000}https\:\/\/cdn\.discordapp\.com\/attachments\// nocase ascii wide
                        $string3 = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.bat\sC\:\\ProgramData\\/ nocase ascii wide
                        $string4 = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.ps1\sC\:\\ProgramData\\/ nocase ascii wide
                        $string5 = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.vbs\sC\:\\ProgramData\\/ nocase ascii wide
                        $string6 = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttps\:\/\/raw\.githubusercontent\.com\// nocase ascii wide

    condition:
        any of them
}