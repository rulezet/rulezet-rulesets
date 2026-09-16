rule webBrowserPassView
{
    meta:
        description = "Detection patterns for the tool 'webBrowserPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webBrowserPassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/web_browser_password\.html/ nocase ascii wide
                        $string2 = /\\WebBrowserPassView\.cfg/ nocase ascii wide
                        $string3 = /\\WebBrowserPassView\.chm/ nocase ascii wide
                        $string4 = /\\WebBrowserPassView_lng\.ini/ nocase ascii wide
                        $string5 = ">Web Browser Password Viewer<" nocase ascii wide
                        $string6 = ">WebBrowserPassView<" nocase ascii wide
                        $string7 = "72c3a786661ee9742cf1d0e3b99b89e976911ed87971695f08487cf42d7fc29d" nocase ascii wide
                        $string8 = "e7542c38e0b979f920fb88b59b25c3d6ae433ca145f7758938b322a71accecae" nocase ascii wide
                        $string9 = /f\:\\temp\\passwords\.html/ nocase ascii wide
                        $string10 = /WebBrowserPassView\.exe/ nocase ascii wide
                        $string11 = /WebBrowserPassView\.zip/ nocase ascii wide

    condition:
        any of them
}