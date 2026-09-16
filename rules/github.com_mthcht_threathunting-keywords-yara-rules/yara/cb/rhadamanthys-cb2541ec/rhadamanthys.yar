rule Rhadamanthys
{
    meta:
        description = "Detection patterns for the tool 'Rhadamanthys' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rhadamanthys"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Xworm v" nocase ascii wide
                        $string2 = /\/XWorm\.exe/ nocase ascii wide
                        $string3 = /\/XWorm\.rar/
                        $string4 = /\\XKlog\.txt/ nocase ascii wide
                        $string5 = /\\XWorm\.config/ nocase ascii wide
                        $string6 = /\\XWorm\.exe/ nocase ascii wide
                        $string7 = /\\XWorm\.rar/ nocase ascii wide
                        $string8 = "9950788284df125c7359aeb91435ed24d59359fac6a74ed73774ca31561cc7ae" nocase ascii wide
                        $string9 = "XWorm-v5-Remote-Access-Tool" nocase ascii wide

    condition:
        any of them
}