rule IEPassView
{
    meta:
        description = "Detection patterns for the tool 'IEPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IEPassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/iepv\.exe/ nocase ascii wide
                        $string2 = /\/toolsdownload\/iepv\.zip/ nocase ascii wide
                        $string3 = /\\iepv\.cfg/ nocase ascii wide
                        $string4 = /\\iepv\.exe/ nocase ascii wide
                        $string5 = /\\IEPV\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string6 = /\\iepv\.zip\.lnk/ nocase ascii wide
                        $string7 = /_iepv\.zip\./ nocase ascii wide
                        $string8 = ">IE Pass View<" nocase ascii wide
                        $string9 = ">IE Passwords Viewer<" nocase ascii wide
                        $string10 = "70aaf2b367b97fa35d599a6db4d08875206ef18c99d8c8c5b5f25e4f5509931a" nocase ascii wide
                        $string11 = "Description'>IE Passwords Viewer" nocase ascii wide
                        $string12 = /iepv\.exe\s\/stext\s/ nocase ascii wide

    condition:
        any of them
}