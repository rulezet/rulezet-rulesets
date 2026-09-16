rule rule_EvilClippy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EvilClippy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilClippy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EvilClippy_offensive_tool_keyword = /\/EvilClippy\-.{0,1000}\.zip/ nocase ascii wide
                        $string2_EvilClippy_offensive_tool_keyword = /\/evilclippy\.cs/ nocase ascii wide
                        $string3_EvilClippy_offensive_tool_keyword = /\/EvilClippy\.git/ nocase ascii wide
                        $string4_EvilClippy_offensive_tool_keyword = /\\EvilClippy\-.{0,1000}\.zip/ nocase ascii wide
                        $string5_EvilClippy_offensive_tool_keyword = /\\evilclippy\.cs/ nocase ascii wide
                        $string6_EvilClippy_offensive_tool_keyword = /_EvilClippy\./ nocase ascii wide
                        $string7_EvilClippy_offensive_tool_keyword = "62eb5977f66221339e954ea9e4947966ad4558966264814a406b93dab8b275df" nocase ascii wide
                        $string8_EvilClippy_offensive_tool_keyword = /EvilClippy\.exe/ nocase ascii wide
                        $string9_EvilClippy_offensive_tool_keyword = "EvilClippy-master" nocase ascii wide
                        $string10_EvilClippy_offensive_tool_keyword = /eviloffice\.exe\s/ nocase ascii wide
                        $string11_EvilClippy_offensive_tool_keyword = /eviloffice\.exe/ nocase ascii wide
                        $string12_EvilClippy_offensive_tool_keyword = "outflanknl/EvilClippy" nocase ascii wide

    condition:
        any of them
}