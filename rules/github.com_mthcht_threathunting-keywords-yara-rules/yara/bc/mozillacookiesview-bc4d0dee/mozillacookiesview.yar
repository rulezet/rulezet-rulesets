rule MozillaCookiesView
{
    meta:
        description = "Detection patterns for the tool 'MozillaCookiesView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MozillaCookiesView"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/mzcv\.exe/ nocase ascii wide
                        $string2 = /\/mzcv\-x64\.zip/ nocase ascii wide
                        $string3 = /\\mzcv\.exe/ nocase ascii wide
                        $string4 = /\\mzcv\-x64\.zip/ nocase ascii wide
                        $string5 = ">MZCookiesView<" nocase ascii wide
                        $string6 = "0fbcaa65ada37326741259d2ebc96d52e61d38cd6c28823194f2ffb4bf906ebe" nocase ascii wide
                        $string7 = "cace36a7ea185c8a675356f6e3eeb5b1d466666f7853aa9813df486c5178cbdf" nocase ascii wide
                        $string8 = /MZCookiesView.{0,1000}cookies\.sqlite/ nocase ascii wide

    condition:
        any of them
}