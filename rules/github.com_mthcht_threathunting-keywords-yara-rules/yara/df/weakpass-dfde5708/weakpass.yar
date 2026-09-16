rule weakpass
{
    meta:
        description = "Detection patterns for the tool 'weakpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "weakpass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/1\/all_in_one\.7z\.torrent/ nocase ascii wide
                        $string2 = /\/1\/all_in_one_p\.7z/ nocase ascii wide
                        $string3 = /\/1\/all_in_one_w\.7z/ nocase ascii wide
                        $string4 = /\/dicassassin\.7z/ nocase ascii wide
                        $string5 = /\/hashesorg2019\.gz/ nocase ascii wide
                        $string6 = /\/weakpass\.git/ nocase ascii wide
                        $string7 = /\/weakpass_2a\.gz/ nocase ascii wide
                        $string8 = /\/weakpass_3a\.7z/ nocase ascii wide
                        $string9 = /\\online_brute\.gz/ nocase ascii wide
                        $string10 = /cyclone\.hashesorg\.hashkiller\.combined/ nocase ascii wide
                        $string11 = /download\.weakpass\.com\// nocase ascii wide
                        $string12 = /github\.io\/weakpass\/generator\// nocase ascii wide
                        $string13 = /https\:\/\/weakpass\.com\// nocase ascii wide
                        $string14 = /js\-cracker\-client\/cracker\.js/ nocase ascii wide
                        $string15 = /online_brute\.gz\.torrent/ nocase ascii wide
                        $string16 = /weakpass\.com\/crack\-js/ nocase ascii wide
                        $string17 = /weakpass\.com\/generate/ nocase ascii wide
                        $string18 = /weakpass\.com\/wordlist\// nocase ascii wide
                        $string19 = "weakpass/crack-js" nocase ascii wide
                        $string20 = /weakpass_3\.7z/ nocase ascii wide
                        $string21 = /weakpass_3a\.7z\.torrent/ nocase ascii wide
                        $string22 = /weakpass\-main\./ nocase ascii wide
                        $string23 = /wordlists.{0,1000}all_in_one\.7z/ nocase ascii wide
                        $string24 = /xsukax\-Wordlist\-All\.7z/ nocase ascii wide
                        $string25 = "zzzteph/weakpass" nocase ascii wide

    condition:
        any of them
}