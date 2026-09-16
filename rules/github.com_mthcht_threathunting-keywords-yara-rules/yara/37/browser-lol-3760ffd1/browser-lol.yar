rule browser_lol
{
    meta:
        description = "Detection patterns for the tool 'browser.lol' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "browser.lol"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "&browser=tor&api=false" nocase ascii wide
                        $string2 = /\.srv\.browser\.lol/ nocase ascii wide
                        $string3 = /browser\.lol\/create/ nocase ascii wide
                        $string4 = /https\:\/\/browser\.lol\/vnc\?server\=/ nocase ascii wide

    condition:
        any of them
}