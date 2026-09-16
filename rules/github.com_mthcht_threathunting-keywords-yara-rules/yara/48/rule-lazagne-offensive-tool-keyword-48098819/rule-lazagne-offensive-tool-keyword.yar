rule rule_LaZagne_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LaZagne' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LaZagne"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LaZagne_offensive_tool_keyword = /\slaZagne\.py/ nocase ascii wide
                        $string2_LaZagne_offensive_tool_keyword = /\smemorydump\.py/ nocase ascii wide
                        $string3_LaZagne_offensive_tool_keyword = "\"The LaZagne project\"" nocase ascii wide
                        $string4_LaZagne_offensive_tool_keyword = /\/creddump7.{0,100}\.py/ nocase ascii wide
                        $string5_LaZagne_offensive_tool_keyword = /\/LaZagne\.git/ nocase ascii wide
                        $string6_LaZagne_offensive_tool_keyword = /\/laZagne\.py/ nocase ascii wide
                        $string7_LaZagne_offensive_tool_keyword = /\/memorydump\.py/ nocase ascii wide
                        $string8_LaZagne_offensive_tool_keyword = /\/pswRecovery4Moz\.txt/ nocase ascii wide
                        $string9_LaZagne_offensive_tool_keyword = "0cb85b94cf22a5eb8c6a391c9546aeeb1d86b7e7ae482b512de0f45c3ed90f26" nocase ascii wide
                        $string10_LaZagne_offensive_tool_keyword = "0cf8787b1bfb746c629b92dc5a471a436105e176d306a2808a636adab4df1508" nocase ascii wide
                        $string11_LaZagne_offensive_tool_keyword = "14268f4b4154d80f6c8a20bd79cca08e829cfef4d5f5c244d968c3652da7a336" nocase ascii wide
                        $string12_LaZagne_offensive_tool_keyword = "26e18c8672146105fd4aed794f8d2305c635117eaea1de3e30b8f91473449b86" nocase ascii wide
                        $string13_LaZagne_offensive_tool_keyword = "32ae965a0b8ea94499ffb0368ae4d5a349f84c5b37ba3cba1874d0bd73dc650c" nocase ascii wide
                        $string14_LaZagne_offensive_tool_keyword = "3cc5ee93a9ba1fc57389705283b760c8bd61f35e9398bbfa3210e2becf6d4b05" nocase ascii wide
                        $string15_LaZagne_offensive_tool_keyword = "3d2b4aa76b770b3421f0867aa68b42a1a17f723df251d81af9459f3a872a6fc4" nocase ascii wide
                        $string16_LaZagne_offensive_tool_keyword = "4347d68bd769cf25fa1046b8c9c3f5f4c1c83ae6b96ac1d3ed4b8dce7647c22c" nocase ascii wide
                        $string17_LaZagne_offensive_tool_keyword = "44acd66093e5cc54cdd68c183815d7c16b48b82aadd03c03bb01f3e03adf17c1" nocase ascii wide
                        $string18_LaZagne_offensive_tool_keyword = "5312f40c37c8be83b7131d03100ca39c7e9862465dd40e62d13f153e4ddf1905" nocase ascii wide
                        $string19_LaZagne_offensive_tool_keyword = "58cd6577c12f1c12a51e8abbe80aa54cd358e7c65a4efa8f28425d98ff0278cc" nocase ascii wide
                        $string20_LaZagne_offensive_tool_keyword = "5a2e947aace9e081ecd2cfa7bc2e485528238555c7eeb6bcca560576d4750a50" nocase ascii wide
                        $string21_LaZagne_offensive_tool_keyword = "6448c50a9a80154c2f1ca5b7525ffc8822f16562b1774a54efd066fcc80620e8" nocase ascii wide
                        $string22_LaZagne_offensive_tool_keyword = "760980ec830603bf3bee659f92e939d2af88eef7bc50c2911cce1a41d35d881d" nocase ascii wide
                        $string23_LaZagne_offensive_tool_keyword = "76d64e0cf551962a2ba20813933207dd398d1d06383c27765874219642218eca" nocase ascii wide
                        $string24_LaZagne_offensive_tool_keyword = "7c9132c6c40c456396370d2e9cec4ee32b8cd289b29ccca946ea79f185eeaeed" nocase ascii wide
                        $string25_LaZagne_offensive_tool_keyword = "853d769d63efcbc5d78f3f81c7cae176bf34c248d3bbbf6f32b4bc5d5de561e8" nocase ascii wide
                        $string26_LaZagne_offensive_tool_keyword = "8b081e47fc6d4ab5dc0483dcc7243ff66911b9e660ab8ad9296a7144e95dbd47" nocase ascii wide
                        $string27_LaZagne_offensive_tool_keyword = "8e068fd6cafac177fcf10e61a2672c0e572180bc20270e47e55525ad027d729d" nocase ascii wide
                        $string28_LaZagne_offensive_tool_keyword = "98ad711010195669ee57216b2b376e81fec7437ceab10ab369fee7598d931a1a" nocase ascii wide
                        $string29_LaZagne_offensive_tool_keyword = "9c46104f36627ea0842bf00c050e6fb43befa60e56369e7d4ea843a198e16323" nocase ascii wide
                        $string30_LaZagne_offensive_tool_keyword = "AlessandroZ/LaZagne" nocase ascii wide
                        $string31_LaZagne_offensive_tool_keyword = /Application\.Lazagne\.H/ nocase ascii wide
                        $string32_LaZagne_offensive_tool_keyword = "b3c2a6fe40c1c3688b2ea12b7211a3573f1fcfb0fc092e20826db40f8a2fba63" nocase ascii wide
                        $string33_LaZagne_offensive_tool_keyword = "c03ef8106c58c8980b7859e0a8ee2363d70e2b7f1346356127c826faf2c0caa3" nocase ascii wide
                        $string34_LaZagne_offensive_tool_keyword = "c3b7a095eb5860b4414e354becc07bf30a9133737164b89b689873ee9f9c7bd6" nocase ascii wide
                        $string35_LaZagne_offensive_tool_keyword = /dumping\spasswords\sfrom\s\%s\s\(pid\:/ nocase ascii wide
                        $string36_LaZagne_offensive_tool_keyword = "ed2f501408a7a6e1a854c29c4b0bc5648a6aa8612432df829008931b3e34bf56" nocase ascii wide
                        $string37_LaZagne_offensive_tool_keyword = "fa8ff7e30ab51f8331ad6d9792d470406de52d66681c2b788361eb578558f913" nocase ascii wide
                        $string38_LaZagne_offensive_tool_keyword = "fd0571eeb3d23326429a47df6b1104383efca78191f36099897ec29e5a4da50e" nocase ascii wide
                        $string39_LaZagne_offensive_tool_keyword = /laZagne\.exe\sbrowsers/ nocase ascii wide
                        $string40_LaZagne_offensive_tool_keyword = /Lazagne\.exe/ nocase ascii wide
                        $string41_LaZagne_offensive_tool_keyword = /Lazagne\.py/ nocase ascii wide
                        $string42_LaZagne_offensive_tool_keyword = /lazagne\.softwares\.sysadmin\.aws/ nocase ascii wide
                        $string43_LaZagne_offensive_tool_keyword = /lazagne\.softwares\.windows/ nocase ascii wide
                        $string44_LaZagne_offensive_tool_keyword = /lazagne\.tar\.gz/ nocase ascii wide
                        $string45_LaZagne_offensive_tool_keyword = /LaZagne\-master\.zip/ nocase ascii wide
                        $string46_LaZagne_offensive_tool_keyword = /memory.{0,100}mimipy\.py/ nocase ascii wide
                        $string47_LaZagne_offensive_tool_keyword = /memory\/onepassword\.py/ nocase ascii wide
                        $string48_LaZagne_offensive_tool_keyword = /memorydump\.py/ nocase ascii wide
                        $string49_LaZagne_offensive_tool_keyword = /mimipy\.py/ nocase ascii wide
                        $string50_LaZagne_offensive_tool_keyword = /windows.{0,100}lsa_secrets\.py/ nocase ascii wide
                        $string51_LaZagne_offensive_tool_keyword = /Windows\/lazagne\.spec/ nocase ascii wide
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