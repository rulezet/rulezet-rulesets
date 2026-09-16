rule rule_SigmaPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SigmaPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SigmaPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SigmaPotato_offensive_tool_keyword = " --revshell" nocase ascii wide
                        $string2_SigmaPotato_offensive_tool_keyword = /\/SigmaPotato\.git/ nocase ascii wide
                        $string3_SigmaPotato_offensive_tool_keyword = "/SigmaPotato/releases/download/" nocase ascii wide
                        $string4_SigmaPotato_offensive_tool_keyword = /\\\\pipe\\\\SigmaPotato/ nocase ascii wide
                        $string5_SigmaPotato_offensive_tool_keyword = /\\pipe\\SigmaPotato/ nocase ascii wide
                        $string6_SigmaPotato_offensive_tool_keyword = /\\SigmaPotato\.csproj/ nocase ascii wide
                        $string7_SigmaPotato_offensive_tool_keyword = "148b284dead436f9dbbc23f7e4861901ddc7f1d2cc03c49b8b0379ff6b5633b4" nocase ascii wide
                        $string8_SigmaPotato_offensive_tool_keyword = "14a0ceba63b3d76d7d30653112a0b43e3a2ef1f07a8030d7a949696b5c3065f6" nocase ascii wide
                        $string9_SigmaPotato_offensive_tool_keyword = "2AE886C3-3272-40BE-8D3C-EBAEDE9E61E1" nocase ascii wide
                        $string10_SigmaPotato_offensive_tool_keyword = "351b7ea09ad99959f21e0c21bef93112ec360ccef4bc0cbaaed390a16631326b" nocase ascii wide
                        $string11_SigmaPotato_offensive_tool_keyword = "37ee54a15c44f222327a9d77243113c2b0efb07451eca2f887d314b6e0963f86" nocase ascii wide
                        $string12_SigmaPotato_offensive_tool_keyword = "4de639c973c8f91cf5e4e9c8078dacbbec2de8443b400c8233f1b5dae48a9444" nocase ascii wide
                        $string13_SigmaPotato_offensive_tool_keyword = "6a2c34b319067eea1310e221cff99ce5150be0a82a822fb280554974f6d60dd2" nocase ascii wide
                        $string14_SigmaPotato_offensive_tool_keyword = "876236cb7297de4232a08d57ff6e5929ad522d150f35a288915f9e0a1d4b9968" nocase ascii wide
                        $string15_SigmaPotato_offensive_tool_keyword = "93052e4a139b6f66aed0be356b47c2816bf121445df85ca5369d024fc06c6f5f" nocase ascii wide
                        $string16_SigmaPotato_offensive_tool_keyword = "a7a1bc83f94696c2ef637e12c28afd5f5cbb8f7d0cf22cb41921d77b6c39a721" nocase ascii wide
                        $string17_SigmaPotato_offensive_tool_keyword = "bcaea27cde09d870a66d227e61d4be463e0d943831c8728612489b0587e34676" nocase ascii wide
                        $string18_SigmaPotato_offensive_tool_keyword = "e17d9c10a343762b54f938c0eaf63f479140792c7a27c876d4bccfe09e5d924c" nocase ascii wide
                        $string19_SigmaPotato_offensive_tool_keyword = "ec68a6bf7f104a815bd21e27e73a8dfb8afcb282d4997bebe9eccd6c89259506" nocase ascii wide
                        $string20_SigmaPotato_offensive_tool_keyword = "ed0baea4cf8c5e3a0dce2db731ab38e324ce9db4269952fd9b90dc007c5d4291" nocase ascii wide
                        $string21_SigmaPotato_offensive_tool_keyword = "f54c0294b0a07f49dc21ec7978c25cc5e75947646832675f1af782384aee911f" nocase ascii wide
                        $string22_SigmaPotato_offensive_tool_keyword = "Invoke-SigmaPotato " nocase ascii wide
                        $string23_SigmaPotato_offensive_tool_keyword = /Invoke\-SigmaPotato\.ps1/ nocase ascii wide
                        $string24_SigmaPotato_offensive_tool_keyword = "ncacn_ip_tcp:fuck you !" nocase ascii wide
                        $string25_SigmaPotato_offensive_tool_keyword = /powershell\s\-e\s\$env\:SigmaBootstrap/ nocase ascii wide
                        $string26_SigmaPotato_offensive_tool_keyword = /SigmaPotato\.exe/ nocase ascii wide
                        $string27_SigmaPotato_offensive_tool_keyword = /SigmaPotatoCore\.exe/ nocase ascii wide
                        $string28_SigmaPotato_offensive_tool_keyword = "tylerdotrar/SigmaPotato" nocase ascii wide
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