rule wordlists
{
    meta:
        description = "Detection patterns for the tool 'wordlists' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wordlists"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install wordlists" nocase ascii wide
                        $string2 = /\s\-u\swordlist\s.{0,1000}\swordlist_uniq_sorted/ nocase ascii wide
                        $string3 = "/amass/wordlists" nocase ascii wide
                        $string4 = "/brutespray/" nocase ascii wide
                        $string5 = "/dirbuster/" nocase ascii wide
                        $string6 = /\/fb_firstlast\.7z/ nocase ascii wide
                        $string7 = "/fern-wifi-cracker/" nocase ascii wide
                        $string8 = /\/rockyou\.txt/ nocase ascii wide
                        $string9 = /\/top_mots_combo\.7z/ nocase ascii wide
                        $string10 = /\/Web\/decouverte\.txt/ nocase ascii wide
                        $string11 = /\/Web\/discovery\.txt/ nocase ascii wide
                        $string12 = /\/wikipedia_fr\.7z/ nocase ascii wide
                        $string13 = /clem9669_wordlist_medium\.7z/ nocase ascii wide
                        $string14 = /clem9669_wordlist_small\.7z/ nocase ascii wide
                        $string15 = "dirb/wordlists" nocase ascii wide
                        $string16 = /fasttrack\/wordlist\.txt/ nocase ascii wide
                        $string17 = /john\/password\.lst/ nocase ascii wide
                        $string18 = /nselib\/data\/passwords\.lst/ nocase ascii wide
                        $string19 = /rockyou\.txt\.gz/ nocase ascii wide
                        $string20 = /sqlmap\/data\/txt\/wordlist\.txt/ nocase ascii wide
                        $string21 = "usr/share/seclists" nocase ascii wide
                        $string22 = "wfuzz/wordlist" nocase ascii wide
                        $string23 = /wordlist_TLAs\.txt/ nocase ascii wide
                        $string24 = /wordlist\-probable\.txt/ nocase ascii wide

    condition:
        any of them
}