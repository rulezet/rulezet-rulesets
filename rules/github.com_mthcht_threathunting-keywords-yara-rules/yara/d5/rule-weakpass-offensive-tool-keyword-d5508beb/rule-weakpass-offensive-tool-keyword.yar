rule rule_weakpass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'weakpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "weakpass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_weakpass_offensive_tool_keyword = /\/1\/all_in_one\.7z\.torrent/ nocase ascii wide
                        $string2_weakpass_offensive_tool_keyword = /\/1\/all_in_one_p\.7z/ nocase ascii wide
                        $string3_weakpass_offensive_tool_keyword = /\/1\/all_in_one_w\.7z/ nocase ascii wide
                        $string4_weakpass_offensive_tool_keyword = /\/dicassassin\.7z/ nocase ascii wide
                        $string5_weakpass_offensive_tool_keyword = /\/hashesorg2019\.gz/ nocase ascii wide
                        $string6_weakpass_offensive_tool_keyword = /\/weakpass\.git/ nocase ascii wide
                        $string7_weakpass_offensive_tool_keyword = /\/weakpass_2a\.gz/ nocase ascii wide
                        $string8_weakpass_offensive_tool_keyword = /\/weakpass_3a\.7z/ nocase ascii wide
                        $string9_weakpass_offensive_tool_keyword = /\\online_brute\.gz/ nocase ascii wide
                        $string10_weakpass_offensive_tool_keyword = /cyclone\.hashesorg\.hashkiller\.combined/ nocase ascii wide
                        $string11_weakpass_offensive_tool_keyword = /download\.weakpass\.com\// nocase ascii wide
                        $string12_weakpass_offensive_tool_keyword = /github\.io\/weakpass\/generator\// nocase ascii wide
                        $string13_weakpass_offensive_tool_keyword = /https\:\/\/weakpass\.com\// nocase ascii wide
                        $string14_weakpass_offensive_tool_keyword = /js\-cracker\-client\/cracker\.js/ nocase ascii wide
                        $string15_weakpass_offensive_tool_keyword = /online_brute\.gz\.torrent/ nocase ascii wide
                        $string16_weakpass_offensive_tool_keyword = /weakpass\.com\/crack\-js/ nocase ascii wide
                        $string17_weakpass_offensive_tool_keyword = /weakpass\.com\/generate/ nocase ascii wide
                        $string18_weakpass_offensive_tool_keyword = /weakpass\.com\/wordlist\// nocase ascii wide
                        $string19_weakpass_offensive_tool_keyword = "weakpass/crack-js" nocase ascii wide
                        $string20_weakpass_offensive_tool_keyword = /weakpass_3\.7z/ nocase ascii wide
                        $string21_weakpass_offensive_tool_keyword = /weakpass_3a\.7z\.torrent/ nocase ascii wide
                        $string22_weakpass_offensive_tool_keyword = /weakpass\-main\./ nocase ascii wide
                        $string23_weakpass_offensive_tool_keyword = /wordlists.{0,1000}all_in_one\.7z/ nocase ascii wide
                        $string24_weakpass_offensive_tool_keyword = /xsukax\-Wordlist\-All\.7z/ nocase ascii wide
                        $string25_weakpass_offensive_tool_keyword = "zzzteph/weakpass" nocase ascii wide

    condition:
        any of them
}