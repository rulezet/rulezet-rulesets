rule rule_wordlists_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wordlists' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wordlists"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wordlists_offensive_tool_keyword = " install wordlists" nocase ascii wide
                        $string2_wordlists_offensive_tool_keyword = /\s\-u\swordlist\s.{0,100}\swordlist_uniq_sorted/ nocase ascii wide
                        $string3_wordlists_offensive_tool_keyword = "/amass/wordlists" nocase ascii wide
                        $string4_wordlists_offensive_tool_keyword = "/brutespray/" nocase ascii wide
                        $string5_wordlists_offensive_tool_keyword = "/dirbuster/" nocase ascii wide
                        $string6_wordlists_offensive_tool_keyword = /\/fb_firstlast\.7z/ nocase ascii wide
                        $string7_wordlists_offensive_tool_keyword = "/fern-wifi-cracker/" nocase ascii wide
                        $string8_wordlists_offensive_tool_keyword = /\/rockyou\.txt/ nocase ascii wide
                        $string9_wordlists_offensive_tool_keyword = /\/top_mots_combo\.7z/ nocase ascii wide
                        $string10_wordlists_offensive_tool_keyword = /\/Web\/decouverte\.txt/ nocase ascii wide
                        $string11_wordlists_offensive_tool_keyword = /\/Web\/discovery\.txt/ nocase ascii wide
                        $string12_wordlists_offensive_tool_keyword = /\/wikipedia_fr\.7z/ nocase ascii wide
                        $string13_wordlists_offensive_tool_keyword = /clem9669_wordlist_medium\.7z/ nocase ascii wide
                        $string14_wordlists_offensive_tool_keyword = /clem9669_wordlist_small\.7z/ nocase ascii wide
                        $string15_wordlists_offensive_tool_keyword = "dirb/wordlists" nocase ascii wide
                        $string16_wordlists_offensive_tool_keyword = /fasttrack\/wordlist\.txt/ nocase ascii wide
                        $string17_wordlists_offensive_tool_keyword = /john\/password\.lst/ nocase ascii wide
                        $string18_wordlists_offensive_tool_keyword = /nselib\/data\/passwords\.lst/ nocase ascii wide
                        $string19_wordlists_offensive_tool_keyword = /rockyou\.txt\.gz/ nocase ascii wide
                        $string20_wordlists_offensive_tool_keyword = /sqlmap\/data\/txt\/wordlist\.txt/ nocase ascii wide
                        $string21_wordlists_offensive_tool_keyword = "usr/share/seclists" nocase ascii wide
                        $string22_wordlists_offensive_tool_keyword = "wfuzz/wordlist" nocase ascii wide
                        $string23_wordlists_offensive_tool_keyword = /wordlist_TLAs\.txt/ nocase ascii wide
                        $string24_wordlists_offensive_tool_keyword = /wordlist\-probable\.txt/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}