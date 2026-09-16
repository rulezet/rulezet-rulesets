rule rule_lyncsmash_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lyncsmash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lyncsmash"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_lyncsmash_offensive_tool_keyword = /\.py\sdiscover\s\-H\sdomain_list\.txt/ nocase ascii wide
                        $string2_lyncsmash_offensive_tool_keyword = /\.py\senum\s\-H\s.{0,1000}\s\-U\s.{0,1000}\.txt\s\-P\s.{0,1000}\.txt\s\-.{0,1000}\.txt/ nocase ascii wide
                        $string3_lyncsmash_offensive_tool_keyword = /\.py\slock\s\-H\s.{0,1000}\s\-u\sadministrator\s\-d\s/ nocase ascii wide
                        $string4_lyncsmash_offensive_tool_keyword = /\/find_domain\.sh/ nocase ascii wide
                        $string5_lyncsmash_offensive_tool_keyword = "/lyncsmash/" nocase ascii wide
                        $string6_lyncsmash_offensive_tool_keyword = /\/wordlists\/owa_directories\.txt/ nocase ascii wide
                        $string7_lyncsmash_offensive_tool_keyword = /\/wordlists\/skype\-directories\.txt/ nocase ascii wide
                        $string8_lyncsmash_offensive_tool_keyword = /1_FindDomain\.sh/ nocase ascii wide
                        $string9_lyncsmash_offensive_tool_keyword = /2_lyncbrute\.sh/ nocase ascii wide
                        $string10_lyncsmash_offensive_tool_keyword = /alexa\-top\-20000\-sites\.txt/ nocase ascii wide
                        $string11_lyncsmash_offensive_tool_keyword = /brute_force_ntlm\.sh/ nocase ascii wide
                        $string12_lyncsmash_offensive_tool_keyword = /find_domain\.sh\s/
                        $string13_lyncsmash_offensive_tool_keyword = "lyncsmash" nocase ascii wide
                        $string14_lyncsmash_offensive_tool_keyword = /lyncsmash\.git/ nocase ascii wide
                        $string15_lyncsmash_offensive_tool_keyword = /lyncsmash\.log/ nocase ascii wide
                        $string16_lyncsmash_offensive_tool_keyword = /lyncsmash\.py/ nocase ascii wide
                        $string17_lyncsmash_offensive_tool_keyword = "lyncsmash-master" nocase ascii wide
                        $string18_lyncsmash_offensive_tool_keyword = /ntlm\-info\.py/ nocase ascii wide
                        $string19_lyncsmash_offensive_tool_keyword = "nyxgeek/lyncsmash" nocase ascii wide

    condition:
        any of them
}