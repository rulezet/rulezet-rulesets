rule rule_xz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_xz_offensive_tool_keyword = /\/bad\-3\-corrupt_lzma2\.xz\s\|\str\s/
                        $string2_xz_offensive_tool_keyword = /\/tests\/files\/good\-large_compressed\.lzma\|eval\s\$i\|tail\s\-c\s\+31265\|/
                        $string3_xz_offensive_tool_keyword = "0f5c81f14171b74fcc9777d302304d964e63ffc2d7b634ef023a7249d9b5d875" nocase ascii wide
                        $string4_xz_offensive_tool_keyword = "2398f4a8e53345325f44bdd9f0cc7401bd9025d736c6d43b372f4dea77bf75b8" nocase ascii wide
                        $string5_xz_offensive_tool_keyword = "319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae" nocase ascii wide
                        $string6_xz_offensive_tool_keyword = "50941ad9fd99db6fca5debc3c89b3e899a9527d7" nocase ascii wide
                        $string7_xz_offensive_tool_keyword = "605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4" nocase ascii wide
                        $string8_xz_offensive_tool_keyword = "654c673c177a2a06c2b240ee07f81dc9096b1626f82855dc67722a5e10bbf6a1" nocase ascii wide
                        $string9_xz_offensive_tool_keyword = "654c673c177a2a06c2b240ee07f81dc9096b1626f82855dc67722a5e10bbf6a1" nocase ascii wide
                        $string10_xz_offensive_tool_keyword = "7de9505c6a9be2ff8b308140d28e9318a6045529f70a48bd7ce4115d263988cb" nocase ascii wide
                        $string11_xz_offensive_tool_keyword = "86fc2c94f8fa3938e3261d0b9eb4836be289f8ae" nocase ascii wide
                        $string12_xz_offensive_tool_keyword = "91ae5ce613fa82b7764401fb12fb8977a0b3c78325faa16f30abeb3dfbe9c71a" nocase ascii wide
                        $string13_xz_offensive_tool_keyword = "b83ee6d62e5e159fa0a16fcad953862a1d567abc5c60aa35dc02aac7efc87870" nocase ascii wide
                        $string14_xz_offensive_tool_keyword = "b83ee6d62e5e159fa0a16fcad953862a1d567abc5c60aa35dc02aac7efc87870" nocase ascii wide
                        $string15_xz_offensive_tool_keyword = "c86c8f8a69c07fbec8dd650c6604bf0c9876261f" nocase ascii wide
                        $string16_xz_offensive_tool_keyword = "d2d99c2dcb17923e9ce1d91e16491527edcdd945aa68e54d83bc6fc927274b05" nocase ascii wide
                        $string17_xz_offensive_tool_keyword = "d2d99c2dcb17923e9ce1d91e16491527edcdd945aa68e54d83bc6fc927274b05" nocase ascii wide
                        $string18_xz_offensive_tool_keyword = "d44d0425769fa2e0b6875e5ca25d45b251bbe98870c6b9bef34f7cea9f84c9c3" nocase ascii wide
                        $string19_xz_offensive_tool_keyword = "d44d0425769fa2e0b6875e5ca25d45b251bbe98870c6b9bef34f7cea9f84c9c3" nocase ascii wide
                        $string20_xz_offensive_tool_keyword = "ece869c6e359a650da3a82c8d26239bde4293a591c0d634815595129654665ae" nocase ascii wide
                        $string21_xz_offensive_tool_keyword = "ece869c6e359a650da3a82c8d26239bde4293a591c0d634815595129654665ae" nocase ascii wide
                        $string22_xz_offensive_tool_keyword = /eval\s\$zrKcKQ/ nocase ascii wide
                        $string23_xz_offensive_tool_keyword = "ffcd092a7d9ec7d79a115e3e98f4509bee3e3977e401967140e2e5de061f8a0b" nocase ascii wide
                        $string24_xz_offensive_tool_keyword = /G1Q\+4a0TgAHnlq2B8BKLZUP6wDHsjX6F5nVtUTU3dBQ/ nocase ascii wide
                        $string25_xz_offensive_tool_keyword = "yolAbejyiejuvnup=Evjtgvsh5okmkAvj"
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