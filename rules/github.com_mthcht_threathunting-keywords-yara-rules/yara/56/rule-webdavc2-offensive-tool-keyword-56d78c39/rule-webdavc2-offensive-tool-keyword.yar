rule rule_WebDavC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WebDavC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WebDavC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WebDavC2_offensive_tool_keyword = /\/WebDavC2\.git/ nocase ascii wide
                        $string2_WebDavC2_offensive_tool_keyword = "Arno0x/WebDavC2" nocase ascii wide
                        $string3_WebDavC2_offensive_tool_keyword = "WebDavC2" nocase ascii wide
                        $string4_WebDavC2_offensive_tool_keyword = /webdavC2\.py/ nocase ascii wide
                        $string5_WebDavC2_offensive_tool_keyword = /WebDavC2\-master\.zip/ nocase ascii wide
                        $string6_WebDavC2_offensive_tool_keyword = /webdavC2server\.py/ nocase ascii wide

    condition:
        any of them
}