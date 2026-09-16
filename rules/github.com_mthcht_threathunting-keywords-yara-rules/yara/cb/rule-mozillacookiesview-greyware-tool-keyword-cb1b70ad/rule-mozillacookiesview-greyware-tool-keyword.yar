rule rule_MozillaCookiesView_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MozillaCookiesView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MozillaCookiesView"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_MozillaCookiesView_greyware_tool_keyword = /\/mzcv\.exe/ nocase ascii wide
                        $string2_MozillaCookiesView_greyware_tool_keyword = /\/mzcv\-x64\.zip/ nocase ascii wide
                        $string3_MozillaCookiesView_greyware_tool_keyword = /\\mzcv\.exe/ nocase ascii wide
                        $string4_MozillaCookiesView_greyware_tool_keyword = /\\mzcv\-x64\.zip/ nocase ascii wide
                        $string5_MozillaCookiesView_greyware_tool_keyword = ">MZCookiesView<" nocase ascii wide
                        $string6_MozillaCookiesView_greyware_tool_keyword = "0fbcaa65ada37326741259d2ebc96d52e61d38cd6c28823194f2ffb4bf906ebe" nocase ascii wide
                        $string7_MozillaCookiesView_greyware_tool_keyword = "cace36a7ea185c8a675356f6e3eeb5b1d466666f7853aa9813df486c5178cbdf" nocase ascii wide
                        $string8_MozillaCookiesView_greyware_tool_keyword = /MZCookiesView.{0,1000}cookies\.sqlite/ nocase ascii wide

    condition:
        any of them
}