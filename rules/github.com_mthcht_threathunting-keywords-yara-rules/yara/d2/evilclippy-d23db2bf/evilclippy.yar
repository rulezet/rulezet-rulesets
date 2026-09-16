rule EvilClippy
{
    meta:
        description = "Detection patterns for the tool 'EvilClippy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilClippy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/EvilClippy\-.{0,1000}\.zip/ nocase ascii wide
                        $string2 = /\/evilclippy\.cs/ nocase ascii wide
                        $string3 = /\/EvilClippy\.git/ nocase ascii wide
                        $string4 = /\\EvilClippy\-.{0,1000}\.zip/ nocase ascii wide
                        $string5 = /\\evilclippy\.cs/ nocase ascii wide
                        $string6 = /_EvilClippy\./ nocase ascii wide
                        $string7 = "62eb5977f66221339e954ea9e4947966ad4558966264814a406b93dab8b275df" nocase ascii wide
                        $string8 = /EvilClippy\.exe/ nocase ascii wide
                        $string9 = "EvilClippy-master" nocase ascii wide
                        $string10 = /eviloffice\.exe\s/ nocase ascii wide
                        $string11 = /eviloffice\.exe/ nocase ascii wide
                        $string12 = "outflanknl/EvilClippy" nocase ascii wide

    condition:
        any of them
}