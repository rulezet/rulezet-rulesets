rule ChromeCookiesView
{
    meta:
        description = "Detection patterns for the tool 'ChromeCookiesView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChromeCookiesView"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\ChromeCookiesView\.cfg/ nocase ascii wide
                        $string2 = "5b992399231bc699bda60ec893e9c5af0ccded956ebfe5d02eaa41cb91fea9c8" nocase ascii wide
                        $string3 = /ChromeCookiesView\.exe/ nocase ascii wide
                        $string4 = /chromecookiesview\.zip/ nocase ascii wide
                        $string5 = /chromecookiesview\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}