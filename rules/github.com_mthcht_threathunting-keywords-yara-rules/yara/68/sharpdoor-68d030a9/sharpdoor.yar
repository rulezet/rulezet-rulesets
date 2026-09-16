rule SharpDoor
{
    meta:
        description = "Detection patterns for the tool 'SharpDoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sSharpDoor\.cs/ nocase ascii wide
                        $string2 = /\sSharpDoor\.exe/ nocase ascii wide
                        $string3 = /\/SharpDoor\.cs/ nocase ascii wide
                        $string4 = /\/SharpDoor\.exe/ nocase ascii wide
                        $string5 = /\/SharpDoor\.git/ nocase ascii wide
                        $string6 = /\/SharpDoor\.git/ nocase ascii wide
                        $string7 = /\[\!\]\sUnhandled\sSharpDoor\sexception/ nocase ascii wide
                        $string8 = /\\SharpDoor\.cs/ nocase ascii wide
                        $string9 = /\\SharpDoor\.exe/ nocase ascii wide
                        $string10 = /\\termsrv\.patch\.dll/ nocase ascii wide
                        $string11 = /\\Users\\Public\\termsrv\.dll/ nocase ascii wide
                        $string12 = /\\Users\\Public\\termsrv\.dll/ nocase ascii wide
                        $string13 = /\\Users\\Public\\termsrv\.patch\.dll/ nocase ascii wide
                        $string14 = "4cec28b4c00002245dffc8346be0cc11" nocase ascii wide
                        $string15 = /Allow\sMultiple\sRDP\s\(Remote\sDesktop\)\sSessions\sBy\sPatching\stermsrv\.dll\sFile/ nocase ascii wide
                        $string16 = "infosecn1nja/SharpDoor" nocase ascii wide
                        $string17 = "infosecn1nja/SharpDoor" nocase ascii wide
                        $string18 = /SharpDoor\.exe/ nocase ascii wide
                        $string19 = "SharpDoor-master" nocase ascii wide
                        $string20 = "SharpDoor-master" nocase ascii wide

    condition:
        any of them
}