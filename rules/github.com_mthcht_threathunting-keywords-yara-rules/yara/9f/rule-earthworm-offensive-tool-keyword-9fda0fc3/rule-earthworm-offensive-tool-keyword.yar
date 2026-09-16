rule rule_EarthWorm_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EarthWorm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EarthWorm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EarthWorm_offensive_tool_keyword = /\/earthworm\.exe/ nocase ascii wide
                        $string2_EarthWorm_offensive_tool_keyword = "/ew -s lcx_listen -"
                        $string3_EarthWorm_offensive_tool_keyword = "/ew -s lcx_slave -"
                        $string4_EarthWorm_offensive_tool_keyword = "/ew -s lcx_tran -"
                        $string5_EarthWorm_offensive_tool_keyword = "/ew -s rcsocks -"
                        $string6_EarthWorm_offensive_tool_keyword = "/ew -s ssocksd -"
                        $string7_EarthWorm_offensive_tool_keyword = /\\earthworm\.exe/ nocase ascii wide
                        $string8_EarthWorm_offensive_tool_keyword = /\\ew\.exe\s\-s\srssocks/ nocase ascii wide
                        $string9_EarthWorm_offensive_tool_keyword = /\\ew_for_win_32\.exe/ nocase ascii wide
                        $string10_EarthWorm_offensive_tool_keyword = "32f5aea45557a6aeec3a769c774b105805828aaaa5ceca7b0b3304e0c7f99894" nocase ascii wide
                        $string11_EarthWorm_offensive_tool_keyword = "32f5aea45557a6aeec3a769c774b105805828aaaa5ceca7b0b3304e0c7f99894" nocase ascii wide
                        $string12_EarthWorm_offensive_tool_keyword = "62b621ead9dd3cc8af73904727d15e469ce06968d274217ac7002fa2f806d8ad" nocase ascii wide
                        $string13_EarthWorm_offensive_tool_keyword = "62b621ead9dd3cc8af73904727d15e469ce06968d274217ac7002fa2f806d8ad" nocase ascii wide
                        $string14_EarthWorm_offensive_tool_keyword = "95d2ea175a231758503f47fa5c3bcbe647327b9deaae76808b6dda647b574ecd" nocase ascii wide
                        $string15_EarthWorm_offensive_tool_keyword = "95d2ea175a231758503f47fa5c3bcbe647327b9deaae76808b6dda647b574ecd" nocase ascii wide
                        $string16_EarthWorm_offensive_tool_keyword = "c254dc53b3cf9c7d81d92f4e060a5c44a4f51a228049fd1e2d90fafa9c0a44ee" nocase ascii wide
                        $string17_EarthWorm_offensive_tool_keyword = "c254dc53b3cf9c7d81d92f4e060a5c44a4f51a228049fd1e2d90fafa9c0a44ee" nocase ascii wide
                        $string18_EarthWorm_offensive_tool_keyword = /rootkiter\.com\/EarthWorm/ nocase ascii wide
                        $string19_EarthWorm_offensive_tool_keyword = /rootkiter\@sectree\.cn/ nocase ascii wide

    condition:
        any of them
}