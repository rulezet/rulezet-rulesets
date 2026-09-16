rule rule_bore_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bore' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bore"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_bore_greyware_tool_keyword = " install bore-cli" nocase ascii wide
                        $string2_bore_greyware_tool_keyword = /\s\-\-to\sbore\.pub/ nocase ascii wide
                        $string3_bore_greyware_tool_keyword = "02006756198c02904d534aa215a4382f39b9f182e6fed9d7c2bbb36f3e2c06f6" nocase ascii wide
                        $string4_bore_greyware_tool_keyword = "079ba7d752899ae9635cc444d27479b0cd314a39a282d114e9940a26fb9f55e7" nocase ascii wide
                        $string5_bore_greyware_tool_keyword = "0c2294231827539891a70bd5b7657c7d1d87f53d13f2c609a32f49ca54440797" nocase ascii wide
                        $string6_bore_greyware_tool_keyword = "24328a6907e7d2783be6817bdd1c2ca6c14aa1cb556caff0e193af56e799ff1a" nocase ascii wide
                        $string7_bore_greyware_tool_keyword = "2b5d0530f54a5cb1aa7e037ab075ba27991bafa83a42555d50fde9245a3eb435" nocase ascii wide
                        $string8_bore_greyware_tool_keyword = "32dc4748174790882d0d962dd7b5a6bf332cb8cd6c8ccf8d75d9ec5cd703274a" nocase ascii wide
                        $string9_bore_greyware_tool_keyword = "33de7cf074cc9aa8850b99ef61fb64e490cdf04f0231d76988b207b3d09cbdae" nocase ascii wide
                        $string10_bore_greyware_tool_keyword = "37206e26ef07932cdc1c9f37bb28242b85c7c895bfcfa0b58c48875e0979daf3" nocase ascii wide
                        $string11_bore_greyware_tool_keyword = "418ad6ef7472d4a0d275bb3912b5c1498e26efd801344f581f6eb63e1076e2c4" nocase ascii wide
                        $string12_bore_greyware_tool_keyword = "466de31afaad2ff25fb1e080ec326c31d4d08bc8639b2c957f3f02f2e5900139" nocase ascii wide
                        $string13_bore_greyware_tool_keyword = "4bc74cda62178ccf38917109af3b74d7612ac1fbc234d9c69f0be49e5b7425ce" nocase ascii wide
                        $string14_bore_greyware_tool_keyword = "568ec361aa33903f8cf1678a5b35592887ea6e3de3fae6a1f752730ca2e8e82c" nocase ascii wide
                        $string15_bore_greyware_tool_keyword = "66ae97d291d0e2d0dae8a8642fb8d2872a6dd0183aff325b7eaedcc911284741" nocase ascii wide
                        $string16_bore_greyware_tool_keyword = "703e2d2c0fa3fb1e6b7f1a5249533072d9d9caeaf7811dbe1750ee43c1ef0501" nocase ascii wide
                        $string17_bore_greyware_tool_keyword = "7f36205ce8bfa40c35723afeee04f94c3a3c978b6076c321b6d108d4c7f04963" nocase ascii wide
                        $string18_bore_greyware_tool_keyword = "a583e31f6c18a593b681896402295f35a903df7bc34faae45914679b3e9751b9" nocase ascii wide
                        $string19_bore_greyware_tool_keyword = "ad5c1453508585d413c083df1571738ae1158b7a83aeab24c456548fb0e4cdbd" nocase ascii wide
                        $string20_bore_greyware_tool_keyword = "ae37bedf1ad63fabd9843da4dc3598e80bc135b820555842cc20cad4f95164ff" nocase ascii wide
                        $string21_bore_greyware_tool_keyword = "ba68f7b9e8eb49325a28ed27d1ff542919952145af371b144cc7effdd0d561d9" nocase ascii wide
                        $string22_bore_greyware_tool_keyword = "bb25b3f72e24573d9695f7bb677500a695ad46ce61b61dae5d13fb035ce071c2" nocase ascii wide
                        $string23_bore_greyware_tool_keyword = "bea23804b59ef8bc8cbd4e03054e2b89baccf01b2640013e3b1b7db85c5f6b2e" nocase ascii wide
                        $string24_bore_greyware_tool_keyword = /bore\slocal\s.{0,100}\s\-\-to\s/ nocase ascii wide
                        $string25_bore_greyware_tool_keyword = "bore server --secret " nocase ascii wide
                        $string26_bore_greyware_tool_keyword = "c9bdea295fc4e88e634edc48697912379334da2c771e6130dc1702e32e70672c" nocase ascii wide
                        $string27_bore_greyware_tool_keyword = "c9e87a3b55c42f86a7fbbb0bd11063d7d601988d8a31db7cf1b7c827654b0dc6" nocase ascii wide
                        $string28_bore_greyware_tool_keyword = "ekzhang/bore" nocase ascii wide
                        $string29_bore_greyware_tool_keyword = "f606f2a59706479d9cab36d16b9c241e204edb46540c92333521872dfcda025f" nocase ascii wide
                        $string30_bore_greyware_tool_keyword = /http\:\/\/bore\.pub\// nocase ascii wide
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