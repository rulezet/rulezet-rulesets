rule SocialBox_Termux
{
    meta:
        description = "Detection patterns for the tool 'SocialBox-Termux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SocialBox-Termux"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sinstabf\.py/ nocase ascii wide
                        $string2 = /\sinstainsane\.sh/ nocase ascii wide
                        $string3 = /\sinstall\-sb\.sh/ nocase ascii wide
                        $string4 = /\sinsTof\.py/ nocase ascii wide
                        $string5 = /\sSocialBox\.sh/ nocase ascii wide
                        $string6 = /\stweetshell\.sh/ nocase ascii wide
                        $string7 = /\/fb\-brute\.pl/ nocase ascii wide
                        $string8 = /\/Gemail\-Hack\.git/ nocase ascii wide
                        $string9 = /\/insta\-bf\.git/ nocase ascii wide
                        $string10 = /\/instabf\.py/ nocase ascii wide
                        $string11 = /\/instainsane\.git/ nocase ascii wide
                        $string12 = /\/instainsane\.sh/ nocase ascii wide
                        $string13 = /\/install\-sb\.sh/ nocase ascii wide
                        $string14 = /\/insTof\.py/ nocase ascii wide
                        $string15 = /\/SocialBox\.sh/ nocase ascii wide
                        $string16 = "/SocialBox-Termux" nocase ascii wide
                        $string17 = "/Sup3r-Us3r/scripts/" nocase ascii wide
                        $string18 = /\/tweetshell\.sh/ nocase ascii wide
                        $string19 = "/umeshshinde19/instainsane" nocase ascii wide
                        $string20 = "apt-get -y install tor " nocase ascii wide
                        $string21 = /Brute\-force\-Instagram\-.{0,100}\.git/ nocase ascii wide
                        $string22 = "datr=80ZzUfKqDOjwL8pauwqMjHTa" nocase ascii wide
                        $string23 = /gemailhack\.py/ nocase ascii wide
                        $string24 = "Ha3MrX/Gemail-Hack" nocase ascii wide
                        $string25 = /Ox\-Bruter\.pl/ nocase ascii wide
                        $string26 = "thelinuxchoice/tweetshell"
                        $string27 = "Yuuup!! Pass Cracked" nocase ascii wide
                        $string28 = "ZxKmz4hXp6XKmTPg9lzgYxXN4sFr2pzo" nocase ascii wide
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