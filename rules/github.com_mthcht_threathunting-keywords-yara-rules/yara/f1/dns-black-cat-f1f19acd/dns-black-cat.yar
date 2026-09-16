rule dns_black_cat
{
    meta:
        description = "Detection patterns for the tool 'dns-black-cat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns-black-cat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " DNS-Black-CAT Server " nocase ascii wide
                        $string2 = /\/DBC\-Server\.py/ nocase ascii wide
                        $string3 = /\/dns\-black\-cat\.git/ nocase ascii wide
                        $string4 = /\/dns\-cat\.exe/ nocase ascii wide
                        $string5 = /\\dns\-cat\.exe/ nocase ascii wide
                        $string6 = /agent\.exe\s\-dns\s\-srvhost\s/ nocase ascii wide
                        $string7 = /dns_server\.py\s\-d\s/ nocase ascii wide
                        $string8 = "dns-black-cat-main" nocase ascii wide
                        $string9 = /dns\-cat\.exe\s\-/ nocase ascii wide
                        $string10 = "lawrenceamer/dns-black-cat" nocase ascii wide

    condition:
        any of them
}