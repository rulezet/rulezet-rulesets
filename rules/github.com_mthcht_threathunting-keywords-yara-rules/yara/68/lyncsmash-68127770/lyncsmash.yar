rule lyncsmash
{
    meta:
        description = "Detection patterns for the tool 'lyncsmash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lyncsmash"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.py\sdiscover\s\-H\sdomain_list\.txt/ nocase ascii wide
                        $string2 = /\.py\senum\s\-H\s.{0,1000}\s\-U\s.{0,1000}\.txt\s\-P\s.{0,1000}\.txt\s\-.{0,1000}\.txt/ nocase ascii wide
                        $string3 = /\.py\slock\s\-H\s.{0,1000}\s\-u\sadministrator\s\-d\s/ nocase ascii wide
                        $string4 = /\/find_domain\.sh/ nocase ascii wide
                        $string5 = "/lyncsmash/" nocase ascii wide
                        $string6 = /\/wordlists\/owa_directories\.txt/ nocase ascii wide
                        $string7 = /\/wordlists\/skype\-directories\.txt/ nocase ascii wide
                        $string8 = /1_FindDomain\.sh/ nocase ascii wide
                        $string9 = /2_lyncbrute\.sh/ nocase ascii wide
                        $string10 = /alexa\-top\-20000\-sites\.txt/ nocase ascii wide
                        $string11 = /brute_force_ntlm\.sh/ nocase ascii wide
                        $string12 = /find_domain\.sh\s/
                        $string13 = "lyncsmash" nocase ascii wide
                        $string14 = /lyncsmash\.git/ nocase ascii wide
                        $string15 = /lyncsmash\.log/ nocase ascii wide
                        $string16 = /lyncsmash\.py/ nocase ascii wide
                        $string17 = "lyncsmash-master" nocase ascii wide
                        $string18 = /ntlm\-info\.py/ nocase ascii wide
                        $string19 = "nyxgeek/lyncsmash" nocase ascii wide

    condition:
        any of them
}