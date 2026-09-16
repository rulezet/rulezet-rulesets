rule rule_browser_lol_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'browser.lol' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "browser.lol"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_browser_lol_greyware_tool_keyword = "&browser=tor&api=false" nocase ascii wide
                        $string2_browser_lol_greyware_tool_keyword = /\.srv\.browser\.lol/ nocase ascii wide
                        $string3_browser_lol_greyware_tool_keyword = /browser\.lol\/create/ nocase ascii wide
                        $string4_browser_lol_greyware_tool_keyword = /https\:\/\/browser\.lol\/vnc\?server\=/ nocase ascii wide

    condition:
        any of them
}