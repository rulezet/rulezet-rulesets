rule rule_webBrowserPassView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'webBrowserPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webBrowserPassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_webBrowserPassView_offensive_tool_keyword = /\/web_browser_password\.html/ nocase ascii wide
                        $string2_webBrowserPassView_offensive_tool_keyword = /\\WebBrowserPassView\.cfg/ nocase ascii wide
                        $string3_webBrowserPassView_offensive_tool_keyword = /\\WebBrowserPassView\.chm/ nocase ascii wide
                        $string4_webBrowserPassView_offensive_tool_keyword = /\\WebBrowserPassView_lng\.ini/ nocase ascii wide
                        $string5_webBrowserPassView_offensive_tool_keyword = ">Web Browser Password Viewer<" nocase ascii wide
                        $string6_webBrowserPassView_offensive_tool_keyword = ">WebBrowserPassView<" nocase ascii wide
                        $string7_webBrowserPassView_offensive_tool_keyword = "72c3a786661ee9742cf1d0e3b99b89e976911ed87971695f08487cf42d7fc29d" nocase ascii wide
                        $string8_webBrowserPassView_offensive_tool_keyword = "e7542c38e0b979f920fb88b59b25c3d6ae433ca145f7758938b322a71accecae" nocase ascii wide
                        $string9_webBrowserPassView_offensive_tool_keyword = /f\:\\temp\\passwords\.html/ nocase ascii wide
                        $string10_webBrowserPassView_offensive_tool_keyword = /WebBrowserPassView\.exe/ nocase ascii wide
                        $string11_webBrowserPassView_offensive_tool_keyword = /WebBrowserPassView\.zip/ nocase ascii wide

    condition:
        any of them
}