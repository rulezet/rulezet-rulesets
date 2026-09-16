rule WebDavC2
{
    meta:
        description = "Detection patterns for the tool 'WebDavC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WebDavC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/WebDavC2\.git/ nocase ascii wide
                        $string2 = "Arno0x/WebDavC2" nocase ascii wide
                        $string3 = "WebDavC2" nocase ascii wide
                        $string4 = /webdavC2\.py/ nocase ascii wide
                        $string5 = /WebDavC2\-master\.zip/ nocase ascii wide
                        $string6 = /webdavC2server\.py/ nocase ascii wide

    condition:
        any of them
}