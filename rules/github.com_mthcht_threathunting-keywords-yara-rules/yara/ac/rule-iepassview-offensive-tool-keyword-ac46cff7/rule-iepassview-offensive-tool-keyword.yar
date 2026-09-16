rule rule_IEPassView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IEPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IEPassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_IEPassView_offensive_tool_keyword = /\/iepv\.exe/ nocase ascii wide
                        $string2_IEPassView_offensive_tool_keyword = /\/toolsdownload\/iepv\.zip/ nocase ascii wide
                        $string3_IEPassView_offensive_tool_keyword = /\\iepv\.cfg/ nocase ascii wide
                        $string4_IEPassView_offensive_tool_keyword = /\\iepv\.exe/ nocase ascii wide
                        $string5_IEPassView_offensive_tool_keyword = /\\IEPV\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string6_IEPassView_offensive_tool_keyword = /\\iepv\.zip\.lnk/ nocase ascii wide
                        $string7_IEPassView_offensive_tool_keyword = /_iepv\.zip\./ nocase ascii wide
                        $string8_IEPassView_offensive_tool_keyword = ">IE Pass View<" nocase ascii wide
                        $string9_IEPassView_offensive_tool_keyword = ">IE Passwords Viewer<" nocase ascii wide
                        $string10_IEPassView_offensive_tool_keyword = "70aaf2b367b97fa35d599a6db4d08875206ef18c99d8c8c5b5f25e4f5509931a" nocase ascii wide
                        $string11_IEPassView_offensive_tool_keyword = "Description'>IE Passwords Viewer" nocase ascii wide
                        $string12_IEPassView_offensive_tool_keyword = /iepv\.exe\s\/stext\s/ nocase ascii wide

    condition:
        any of them
}