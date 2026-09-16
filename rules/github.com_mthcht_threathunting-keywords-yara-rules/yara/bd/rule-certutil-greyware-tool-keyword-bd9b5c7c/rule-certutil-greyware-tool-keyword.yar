rule rule_certutil_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'certutil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "certutil"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_certutil_greyware_tool_keyword = /certutil\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.exe/ nocase ascii wide
                        $string2_certutil_greyware_tool_keyword = /certutil\.exe\s\-urlcache\s\-split\s\-f\s.{0,1000}https\:\/\/cdn\.discordapp\.com\/attachments\// nocase ascii wide
                        $string3_certutil_greyware_tool_keyword = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.bat\sC\:\\ProgramData\\/ nocase ascii wide
                        $string4_certutil_greyware_tool_keyword = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.ps1\sC\:\\ProgramData\\/ nocase ascii wide
                        $string5_certutil_greyware_tool_keyword = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.vbs\sC\:\\ProgramData\\/ nocase ascii wide
                        $string6_certutil_greyware_tool_keyword = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttps\:\/\/raw\.githubusercontent\.com\// nocase ascii wide

    condition:
        any of them
}