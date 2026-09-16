rule VenomousSway
{
    meta:
        description = "Detection patterns for the tool 'VenomousSway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VenomousSway"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sAddTrustedDomain\.py/ nocase ascii wide
                        $string2 = /\sAddTrustedDomain\.vba/ nocase ascii wide
                        $string3 = /\sBrtoVenomRenames\.sh/ nocase ascii wide
                        $string4 = /\sCorrupt_AMSI\.py/ nocase ascii wide
                        $string5 = /\sCorrupt_AMSI\.vba/ nocase ascii wide
                        $string6 = /\sEnableAllMacros_AMSI\.py/ nocase ascii wide
                        $string7 = /\sEnableAllMacros_AMSI\.vba/ nocase ascii wide
                        $string8 = /\sPatch_AMSI\.py/ nocase ascii wide
                        $string9 = /\sPatch_AMSI\.vba/ nocase ascii wide
                        $string10 = /\sshellcode2vba\.py/ nocase ascii wide
                        $string11 = /\sshellcode2vbafunc\.py/ nocase ascii wide
                        $string12 = /\svenomoussway\.py/ nocase ascii wide
                        $string13 = /\/AddTrustedDomain\.py/ nocase ascii wide
                        $string14 = /\/AddTrustedDomain\.vba/ nocase ascii wide
                        $string15 = /\/BrtoVenomRenames\.sh/ nocase ascii wide
                        $string16 = /\/Corrupt_AMSI\.py/ nocase ascii wide
                        $string17 = /\/Corrupt_AMSI\.vba/ nocase ascii wide
                        $string18 = /\/data\/payload\.log/
                        $string19 = /\/EnableAllMacros_AMSI\.py/ nocase ascii wide
                        $string20 = /\/EnableAllMacros_AMSI\.vba/ nocase ascii wide
                        $string21 = /\/Patch_AMSI\.py/ nocase ascii wide
                        $string22 = /\/Patch_AMSI\.vba/ nocase ascii wide
                        $string23 = /\/shellcode2vba\.py/ nocase ascii wide
                        $string24 = /\/shellcode2vbafunc\.py/ nocase ascii wide
                        $string25 = /\/venomoussway\.py/ nocase ascii wide
                        $string26 = /\\AddTrustedDomain\.py/ nocase ascii wide
                        $string27 = /\\AddTrustedDomain\.vba/ nocase ascii wide
                        $string28 = /\\Corrupt_AMSI\.py/ nocase ascii wide
                        $string29 = /\\Corrupt_AMSI\.vba/ nocase ascii wide
                        $string30 = /\\EnableAllMacros_AMSI\.py/ nocase ascii wide
                        $string31 = /\\EnableAllMacros_AMSI\.vba/ nocase ascii wide
                        $string32 = /\\Patch_AMSI\.py/ nocase ascii wide
                        $string33 = /\\Patch_AMSI\.vba/ nocase ascii wide
                        $string34 = /\\shellcode2vba\.py/ nocase ascii wide
                        $string35 = /\\shellcode2vbafunc\.py/ nocase ascii wide
                        $string36 = /\\venomoussway\.py/ nocase ascii wide
                        $string37 = "1b209500451ebe2bbe420a1ff33d946fa9e9e00399abda9ebcf9b0258fbe7902" nocase ascii wide
                        $string38 = "1e1f0cff-ff7a-406d-bd82-e53809a5e93a" nocase ascii wide
                        $string39 = "1ecac46b693f7ac81d6ac3198742d5b7729391f2ddc5c908f4a665c92c7dec7d" nocase ascii wide
                        $string40 = "2d69f2dcc84e24a3b4f8c8a465f0b3b27f30ce4d24d81e96079deeec0d540f41" nocase ascii wide
                        $string41 = "33bd8a0ee9aba1b5c63f44d993def62986b98ca01590bc1bf2638190b2dd5961" nocase ascii wide
                        $string42 = "40a7ea977e0b28240c6b53f0b5ee130050545aa06cce4ef21afb7f82645cd0cb" nocase ascii wide
                        $string43 = "5248816fad594b75b1f9c63e79ad931f24a346915c7ba2c50035e5c13cced4cf" nocase ascii wide
                        $string44 = "56b15b80abb7b1bd3bb80d41347fcd9d26668499220a1dcd7d292714fbd7d350" nocase ascii wide
                        $string45 = "57ef38c793bc416b93685ed0d2b44971860a2026a7dd9eff7dd2cd5cc6630120" nocase ascii wide
                        $string46 = "63caa714b73110ab5d2e14db8fcddc0ddea627f5bd92bcfacb9d2c6e507e6a84" nocase ascii wide
                        $string47 = "72efc44a791fceb9bc6e602fc079c8bf8139024dec0e580ed15f8c4fe80457bd" nocase ascii wide
                        $string48 = "755c1d8c2e4d58422ec4da20479b10857e1e556331af09975929d13b6b5cbd53" nocase ascii wide
                        $string49 = "766853465051ea9902106a4f90e84bf5b2bd3f4573f591b02f3882b13beafe85" nocase ascii wide
                        $string50 = "77b5efcc93bb859a7c5667dd2e21c7cc2fb7d9bef1237875bb4dbfb1c96cc194" nocase ascii wide
                        $string51 = "7e7c5b1923a84ddf3fcf224536dd9c917bd12ce73d5e512ee293fb6f44dc1bb4" nocase ascii wide
                        $string52 = "8D907846-455E-39A7-BD31-BC9F81468B47" nocase ascii wide
                        $string53 = "8D907846-455E-39A7-BD31-BC9F81468B47" nocase ascii wide
                        $string54 = "987001995ecb92cb1fa659097e4be63c46568c00e4f91ed0162d0ed973831c50" nocase ascii wide
                        $string55 = "9bb0c39f776edc0869cb86fd3de17fccfde02dffe82290dde30997ca10e864fb" nocase ascii wide
                        $string56 = "ad5c08c647f8042f9d4a29581f2c740bb0634404f140cb585ad8175376adaa64" nocase ascii wide
                        $string57 = "ae866775c318b21e13caa37dbfd2b96c03de3ba73522f437c14cc5844270c415" nocase ascii wide
                        $string58 = "b834cbb559fcc9f0dcea0b9303b2006f14d239964b87e6f37d44d5520b93ca0d" nocase ascii wide
                        $string59 = "b95885582cc9fc5ac5491deeb5469e36b5eacafd2699579c3a8eeb6ce1a9e0dd" nocase ascii wide
                        $string60 = "bd4f617afbe887d10f2e971d98b36c62e0d0bb14a8020c16e308f2a6543ae27c" nocase ascii wide
                        $string61 = "be5f14ffdc5bb327e53934a9ef6c55500e8d4ffd920a77df0b6ae209793567a5" nocase ascii wide
                        $string62 = /BinaryToVbaFunc\(/ nocase ascii wide
                        $string63 = "ccf676c0d9c215b6de3a3219688e3f5e20a7a21191ef6a25b382c2c0ec19a7e2" nocase ascii wide
                        $string64 = "cd618bc8eaec4bf2397840938f63f50ddea5458918186a249af976bd081e166e" nocase ascii wide
                        $string65 = "D0CBA7AF-93F5-378A-BB11-2A5D9AA9C4D7" nocase ascii wide
                        $string66 = "D0CBA7AF-93F5-378A-BB11-2A5D9AA9C4D7" nocase ascii wide
                        $string67 = "d4254babd731bc584ca2e41f98f2f570b43ba92dcfbb0e0bee1cab109a5b096c" nocase ascii wide
                        $string68 = /DEBUG\-preobfuscation\.vba/ nocase ascii wide
                        $string69 = /DUAR_Survey_v3\-cleanedx64\.bin/ nocase ascii wide
                        $string70 = /DUAR_Survey_v3\-cleanedx86\.bin/ nocase ascii wide
                        $string71 = /DUAR_Survey_v4\-cleanedx64\.bin/ nocase ascii wide
                        $string72 = /DUAR_Survey_v4\-cleanedx86\.bin/ nocase ascii wide
                        $string73 = "e4ed972586dead9a986aaec11cf76e5e044549b69b2fb9bbf5a685f281997bc8" nocase ascii wide
                        $string74 = "e532449171a8fb15657347c2b6df8391c93227af3fb386011a4e8b40d780ad24" nocase ascii wide
                        $string75 = "FA2052FB-9E23-43C8-A0EF-43BBB710DC61" nocase ascii wide
                        $string76 = "fc8a13a2f3a3a9d94a0b82c0a95fd6baced84cab1c0debfa7df2f3331dd3e31d" nocase ascii wide
                        $string77 = /lib\.obfuscator\.randomizers\.vbarandomizer/ nocase ascii wide
                        $string78 = "name of the generated VBA module to include as a payload" nocase ascii wide
                        $string79 = /payloads\\payloadx64\.bin/ nocase ascii wide
                        $string80 = /payloads\\payloadx86\.bin/ nocase ascii wide
                        $string81 = /ppid_shellcode_spawn\.bin/ nocase ascii wide
                        $string82 = /ppidShellcodeSpawn4\-cleaned\.bin/ nocase ascii wide
                        $string83 = /ppidShellcodeSpawn\-cleaned\.bin/ nocase ascii wide
                        $string84 = /Shellcode2VBA\(/ nocase ascii wide
                        $string85 = /Shellcode2VBAFunc\(/ nocase ascii wide
                        $string86 = "Shellcode2VBAFunc" nocase ascii wide
                        $string87 = /stagers\/mytest_reverse_http\.bin/ nocase ascii wide
                        $string88 = /stagers\/mytest_reverse_https\.bin/ nocase ascii wide
                        $string89 = /stagers\/x64_mytest_reverse_http\.bin/ nocase ascii wide
                        $string90 = /stagers\/x64_mytest_reverse_https\.bin/ nocase ascii wide
                        $string91 = /Staging_w_padding_3\.5_x64\-cleaned\.bin/ nocase ascii wide
                        $string92 = /Staging_w_padding_3\.5_x86\-cleaned\.bin/ nocase ascii wide
                        $string93 = /Staging_w_padding_4\.X_x64\-cleaned\.bin/ nocase ascii wide
                        $string94 = /Staging_w_padding_4\.X_x86\-cleaned\.bin/ nocase ascii wide
                        $string95 = /Staging_w_padding_v3_x64\-cleaned\.bin/ nocase ascii wide
                        $string96 = /Staging_w_padding_v3_x86\-cleaned\.bin/ nocase ascii wide
                        $string97 = /Staging_w_padding_v4_x64\-cleaned\.bin/ nocase ascii wide
                        $string98 = /Staging_w_padding_v4_x86\-cleaned\.bin/ nocase ascii wide
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