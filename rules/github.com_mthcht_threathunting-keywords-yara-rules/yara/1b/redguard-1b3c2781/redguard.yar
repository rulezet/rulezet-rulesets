rule RedGuard
{
    meta:
        description = "Detection patterns for the tool 'RedGuard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedGuard"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/RedGuard/
                        $string2 = /\/RedGuard\.git/ nocase ascii wide
                        $string3 = /\/RedGuard\.go/ nocase ascii wide
                        $string4 = "/RedGuard_32" nocase ascii wide
                        $string5 = "/RedGuard_64" nocase ascii wide
                        $string6 = "/wikiZ/RedGuard" nocase ascii wide
                        $string7 = /\\RedGuard\s\-/ nocase ascii wide
                        $string8 = "866e5289337ab033f89bc57c5274c7ca" nocase ascii wide
                        $string9 = /OverrideLHOST\s360\.com/ nocase ascii wide
                        $string10 = /RedGuard\.log/ nocase ascii wide
                        $string11 = "RedGuard/core" nocase ascii wide
                        $string12 = /RedGuard_x64\.exe/ nocase ascii wide
                        $string13 = /RedGuard_x86\.exe/ nocase ascii wide

    condition:
        any of them
}