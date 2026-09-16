rule rule_RunasCs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RunasCs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RunasCs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RunasCs_offensive_tool_keyword = " --remote-impersonation" nocase ascii wide
                        $string2_RunasCs_offensive_tool_keyword = /\sRunasCs\.cs/ nocase ascii wide
                        $string3_RunasCs_offensive_tool_keyword = /\s\-Username\s.{0,100}\s\-Password\s.{0,100}\s\-Command\s.{0,100}\s\-LogonType\s/ nocase ascii wide
                        $string4_RunasCs_offensive_tool_keyword = /\$RunasCsBase64/ nocase ascii wide
                        $string5_RunasCs_offensive_tool_keyword = /\/RunasCs\.cs/ nocase ascii wide
                        $string6_RunasCs_offensive_tool_keyword = /\/RunasCs\.exe/ nocase ascii wide
                        $string7_RunasCs_offensive_tool_keyword = /\/RunasCs\.git/ nocase ascii wide
                        $string8_RunasCs_offensive_tool_keyword = /\/RunasCs\.zip/ nocase ascii wide
                        $string9_RunasCs_offensive_tool_keyword = /\/RunasCs\.zip/ nocase ascii wide
                        $string10_RunasCs_offensive_tool_keyword = "/RunasCs/releases/download/" nocase ascii wide
                        $string11_RunasCs_offensive_tool_keyword = /\/RunasCs_binaries\.zip/ nocase ascii wide
                        $string12_RunasCs_offensive_tool_keyword = /\/RunasCs_x86\.zip/ nocase ascii wide
                        $string13_RunasCs_offensive_tool_keyword = /\\RunasCs\.cs/ nocase ascii wide
                        $string14_RunasCs_offensive_tool_keyword = /\\RunasCs\.exe/ nocase ascii wide
                        $string15_RunasCs_offensive_tool_keyword = /\\RunasCs\.zip/ nocase ascii wide
                        $string16_RunasCs_offensive_tool_keyword = /\\RunasCs_binaries\.zip/ nocase ascii wide
                        $string17_RunasCs_offensive_tool_keyword = /\\RunasCs_x86\.zip/ nocase ascii wide
                        $string18_RunasCs_offensive_tool_keyword = "041a1f05935a0aae4c4073a55cb9ddd0f356f3f9d5b9fd2355d6332961a226a5" nocase ascii wide
                        $string19_RunasCs_offensive_tool_keyword = "0d624761a03e400013f8372b931e658ceafef28f87574fc3af0421264ebbcb09" nocase ascii wide
                        $string20_RunasCs_offensive_tool_keyword = "168ca61eb4b45c7aa5b3b60df22a0d8122dee8d127a9b8a8e3ec5f427466edf9" nocase ascii wide
                        $string21_RunasCs_offensive_tool_keyword = "24722c45c461dfbcd1e5c9d2cba90bbc6fb32d2bff58b8fbbfb18a852f7eebde" nocase ascii wide
                        $string22_RunasCs_offensive_tool_keyword = "29df50927dfff1414f643367fcc9492dba40ebd2f518e1ec6cce25339ee73f6e" nocase ascii wide
                        $string23_RunasCs_offensive_tool_keyword = "433b8dd9a46d99f08c74b3ed9989848fe2e90498fbdac603b27812fb89be9340" nocase ascii wide
                        $string24_RunasCs_offensive_tool_keyword = "4b25648a17919f5d25080b160d998f02ace0c1fd3aab334dfe8ea53612cca954" nocase ascii wide
                        $string25_RunasCs_offensive_tool_keyword = "69058ca0c4eada431047c0376db8a4728feffbacebbb9578e59f4c9113a342ca" nocase ascii wide
                        $string26_RunasCs_offensive_tool_keyword = "69720fc90a8dca0c2ff3f33a59042ae0a6ddedd64d5fafefbc43583aa770e175" nocase ascii wide
                        $string27_RunasCs_offensive_tool_keyword = "780af7e91e49cdbbc34d44021232c4bb5df42b1584dd35b13a35c8cb670d2c0e" nocase ascii wide
                        $string28_RunasCs_offensive_tool_keyword = "847ff5d91e3c34f2e446ee6f6e2c76c9aafc25c76b031c9f8f45193840571176" nocase ascii wide
                        $string29_RunasCs_offensive_tool_keyword = "885a208a7a8ea9e37a44cef5ec2d8ee8ec7240e97b7ee7b9bda5dbf03553bf75" nocase ascii wide
                        $string30_RunasCs_offensive_tool_keyword = "88f826096be1ed1be32dd45dc2381189df7c5f349c7b808edb872e68be4a9350" nocase ascii wide
                        $string31_RunasCs_offensive_tool_keyword = "89269edf8f752740d81254dd68ae0c8ed29d18cfb8582620e4759b48ad47ddb3" nocase ascii wide
                        $string32_RunasCs_offensive_tool_keyword = "8a1699ce5630406091ec92ceec25f46a587888d228f3a9322dbaf9857cb3b5b7" nocase ascii wide
                        $string33_RunasCs_offensive_tool_keyword = "9e53f4d6daccf2c7f5f8acbe56160e6f7301f3bdd05e067cb2be6c7f17e0c482" nocase ascii wide
                        $string34_RunasCs_offensive_tool_keyword = "9f17e90125023767fcb54bc9573f20b89a50772134e502f92832b6b00df68768" nocase ascii wide
                        $string35_RunasCs_offensive_tool_keyword = "antonioCoco/RunasCs" nocase ascii wide
                        $string36_RunasCs_offensive_tool_keyword = /base64_conversion_commands\.ps1/ nocase ascii wide
                        $string37_RunasCs_offensive_tool_keyword = /\-\-bypass\-uac.{0,100}\-\-logontype/ nocase ascii wide
                        $string38_RunasCs_offensive_tool_keyword = "c235329bd192781dad37dc190bbce353f3f7ade3a98b6d1c79e2ab69a91f26ff" nocase ascii wide
                        $string39_RunasCs_offensive_tool_keyword = /cmd\s\/c\s.{0,100}\s\-\-bypass\-uac/ nocase ascii wide
                        $string40_RunasCs_offensive_tool_keyword = /cmd\s\/c\s.{0,100}\s\-\-remote\-impersonation/ nocase ascii wide
                        $string41_RunasCs_offensive_tool_keyword = "d7568417704e64ca524b45240eadd4ddabfb1f477f9eecc37f6bc5654ee7d184" nocase ascii wide
                        $string42_RunasCs_offensive_tool_keyword = "db5edbf21647b80f858790642c32e9c41884339b505d62ceebcfabb74a44db15" nocase ascii wide
                        $string43_RunasCs_offensive_tool_keyword = "e470b90efe8da89e3c118eea1d62eea1f4f0194d82522c7dfb2a07d24471566a" nocase ascii wide
                        $string44_RunasCs_offensive_tool_keyword = "e70c4d485153cf47b9dde0d1124b48e929e9838e241956b0062fafcd51a2f4f6" nocase ascii wide
                        $string45_RunasCs_offensive_tool_keyword = "Invoke-RunasCs -" nocase ascii wide
                        $string46_RunasCs_offensive_tool_keyword = "Invoke-RunasCs" nocase ascii wide
                        $string47_RunasCs_offensive_tool_keyword = "Invoke-RunasCs" nocase ascii wide
                        $string48_RunasCs_offensive_tool_keyword = /Invoke\-RunasCs\.ps1/ nocase ascii wide
                        $string49_RunasCs_offensive_tool_keyword = "'Product'>RunasCs<" nocase ascii wide
                        $string50_RunasCs_offensive_tool_keyword = "RunasCreateProcessAsUserW" nocase ascii wide
                        $string51_RunasCs_offensive_tool_keyword = /RunasCs\sv1\.5\s\-\s\@splinter_code/ nocase ascii wide
                        $string52_RunasCs_offensive_tool_keyword = /RunasCs.{0,100}\s\-\-remote\-impersonation/ nocase ascii wide
                        $string53_RunasCs_offensive_tool_keyword = /RunasCs\.exe/ nocase ascii wide
                        $string54_RunasCs_offensive_tool_keyword = /RunasCs\.zip/ nocase ascii wide
                        $string55_RunasCs_offensive_tool_keyword = /RunasCs_net2\.exe/ nocase ascii wide
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