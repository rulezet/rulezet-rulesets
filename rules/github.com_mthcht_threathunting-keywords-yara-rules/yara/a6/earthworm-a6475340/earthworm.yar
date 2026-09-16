rule EarthWorm
{
    meta:
        description = "Detection patterns for the tool 'EarthWorm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EarthWorm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/earthworm\.exe/ nocase ascii wide
                        $string2 = "/ew -s lcx_listen -"
                        $string3 = "/ew -s lcx_slave -"
                        $string4 = "/ew -s lcx_tran -"
                        $string5 = "/ew -s rcsocks -"
                        $string6 = "/ew -s ssocksd -"
                        $string7 = /\\earthworm\.exe/ nocase ascii wide
                        $string8 = /\\ew\.exe\s\-s\srssocks/ nocase ascii wide
                        $string9 = /\\ew_for_win_32\.exe/ nocase ascii wide
                        $string10 = "32f5aea45557a6aeec3a769c774b105805828aaaa5ceca7b0b3304e0c7f99894" nocase ascii wide
                        $string11 = "32f5aea45557a6aeec3a769c774b105805828aaaa5ceca7b0b3304e0c7f99894" nocase ascii wide
                        $string12 = "62b621ead9dd3cc8af73904727d15e469ce06968d274217ac7002fa2f806d8ad" nocase ascii wide
                        $string13 = "62b621ead9dd3cc8af73904727d15e469ce06968d274217ac7002fa2f806d8ad" nocase ascii wide
                        $string14 = "95d2ea175a231758503f47fa5c3bcbe647327b9deaae76808b6dda647b574ecd" nocase ascii wide
                        $string15 = "95d2ea175a231758503f47fa5c3bcbe647327b9deaae76808b6dda647b574ecd" nocase ascii wide
                        $string16 = "c254dc53b3cf9c7d81d92f4e060a5c44a4f51a228049fd1e2d90fafa9c0a44ee" nocase ascii wide
                        $string17 = "c254dc53b3cf9c7d81d92f4e060a5c44a4f51a228049fd1e2d90fafa9c0a44ee" nocase ascii wide
                        $string18 = /rootkiter\.com\/EarthWorm/ nocase ascii wide
                        $string19 = /rootkiter\@sectree\.cn/ nocase ascii wide

    condition:
        any of them
}