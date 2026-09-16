rule dnscat
{
    meta:
        description = "Detection patterns for the tool 'dnscat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-dns\sdomain\=skullseclabs\.org/
                        $string2 = /\.\/dnscat/
                        $string3 = /\/dnscat\.c/
                        $string4 = /\/dnscat2\.git/ nocase ascii wide
                        $string5 = /0\.0\.0\.0\:53531/ nocase ascii wide
                        $string6 = /127\.0\.0\.1\:53531/ nocase ascii wide
                        $string7 = /data\/wordlist_256\.txt/
                        $string8 = "dnscat -"
                        $string9 = "dnscat --dns "
                        $string10 = "dnscat tcpcat"
                        $string11 = "dnscat"
                        $string12 = /dnscat2.{0,1000}\.tar\.bz2/
                        $string13 = /dnscat2\-.{0,1000}\.zip/
                        $string14 = /dnscat2\./
                        $string15 = "dnscat2/"
                        $string16 = "dnscat2-server" nocase ascii wide
                        $string17 = /dnscat2\-win32\.exe/ nocase ascii wide
                        $string18 = /dnsmastermind\.rb/
                        $string19 = "localhost:53531"
                        $string20 = /server\=.{0,1000}port\=53531/

    condition:
        any of them
}