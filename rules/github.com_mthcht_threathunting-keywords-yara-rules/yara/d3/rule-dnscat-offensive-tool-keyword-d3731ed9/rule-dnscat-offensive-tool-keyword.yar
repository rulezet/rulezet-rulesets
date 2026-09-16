rule rule_dnscat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnscat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnscat_offensive_tool_keyword = /\s\-\-dns\sdomain\=skullseclabs\.org/
                        $string2_dnscat_offensive_tool_keyword = /\.\/dnscat/
                        $string3_dnscat_offensive_tool_keyword = /\/dnscat\.c/
                        $string4_dnscat_offensive_tool_keyword = /\/dnscat2\.git/ nocase ascii wide
                        $string5_dnscat_offensive_tool_keyword = /0\.0\.0\.0\:53531/ nocase ascii wide
                        $string6_dnscat_offensive_tool_keyword = /127\.0\.0\.1\:53531/ nocase ascii wide
                        $string7_dnscat_offensive_tool_keyword = /data\/wordlist_256\.txt/
                        $string8_dnscat_offensive_tool_keyword = "dnscat -"
                        $string9_dnscat_offensive_tool_keyword = "dnscat --dns "
                        $string10_dnscat_offensive_tool_keyword = "dnscat tcpcat"
                        $string11_dnscat_offensive_tool_keyword = "dnscat"
                        $string12_dnscat_offensive_tool_keyword = /dnscat2.{0,1000}\.tar\.bz2/
                        $string13_dnscat_offensive_tool_keyword = /dnscat2\-.{0,1000}\.zip/
                        $string14_dnscat_offensive_tool_keyword = /dnscat2\./
                        $string15_dnscat_offensive_tool_keyword = "dnscat2/"
                        $string16_dnscat_offensive_tool_keyword = "dnscat2-server" nocase ascii wide
                        $string17_dnscat_offensive_tool_keyword = /dnscat2\-win32\.exe/ nocase ascii wide
                        $string18_dnscat_offensive_tool_keyword = /dnsmastermind\.rb/
                        $string19_dnscat_offensive_tool_keyword = "localhost:53531"
                        $string20_dnscat_offensive_tool_keyword = /server\=.{0,1000}port\=53531/

    condition:
        any of them
}