rule rule_dns_black_cat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dns-black-cat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns-black-cat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dns_black_cat_offensive_tool_keyword = " DNS-Black-CAT Server " nocase ascii wide
                        $string2_dns_black_cat_offensive_tool_keyword = /\/DBC\-Server\.py/ nocase ascii wide
                        $string3_dns_black_cat_offensive_tool_keyword = /\/dns\-black\-cat\.git/ nocase ascii wide
                        $string4_dns_black_cat_offensive_tool_keyword = /\/dns\-cat\.exe/ nocase ascii wide
                        $string5_dns_black_cat_offensive_tool_keyword = /\\dns\-cat\.exe/ nocase ascii wide
                        $string6_dns_black_cat_offensive_tool_keyword = /agent\.exe\s\-dns\s\-srvhost\s/ nocase ascii wide
                        $string7_dns_black_cat_offensive_tool_keyword = /dns_server\.py\s\-d\s/ nocase ascii wide
                        $string8_dns_black_cat_offensive_tool_keyword = "dns-black-cat-main" nocase ascii wide
                        $string9_dns_black_cat_offensive_tool_keyword = /dns\-cat\.exe\s\-/ nocase ascii wide
                        $string10_dns_black_cat_offensive_tool_keyword = "lawrenceamer/dns-black-cat" nocase ascii wide

    condition:
        any of them
}