rule rule_NetRipper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetRipper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetRipper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NetRipper_offensive_tool_keyword = /\sNetRipper\.dll/ nocase ascii wide
                        $string2_NetRipper_offensive_tool_keyword = /\.DLL\sinjection\scomplete\!/ nocase ascii wide
                        $string3_NetRipper_offensive_tool_keyword = /\.exe\s\-w\s.{0,100}\.dll\s\-l\sTEMP\s\-p\strue\s\-d\s4096\s\-s\suser\,pass/ nocase ascii wide
                        $string4_NetRipper_offensive_tool_keyword = /\/NetRipper\.dll/ nocase ascii wide
                        $string5_NetRipper_offensive_tool_keyword = /\/NetRipper\.exe/ nocase ascii wide
                        $string6_NetRipper_offensive_tool_keyword = /\/NetRipper\.git/ nocase ascii wide
                        $string7_NetRipper_offensive_tool_keyword = /\/NetRipper\.x64\.exe/ nocase ascii wide
                        $string8_NetRipper_offensive_tool_keyword = /\/NetRipper\.x86\.exe/ nocase ascii wide
                        $string9_NetRipper_offensive_tool_keyword = /\/NetRipperLog\.txt/
                        $string10_NetRipper_offensive_tool_keyword = "/windows/gather/netripper" nocase ascii wide
                        $string11_NetRipper_offensive_tool_keyword = /\\InjectedDLL\.cpp/ nocase ascii wide
                        $string12_NetRipper_offensive_tool_keyword = /\\NetRipper\.cpp/ nocase ascii wide
                        $string13_NetRipper_offensive_tool_keyword = /\\NetRipper\.dll/ nocase ascii wide
                        $string14_NetRipper_offensive_tool_keyword = /\\NetRipper\.exe/ nocase ascii wide
                        $string15_NetRipper_offensive_tool_keyword = /\\netripper\.rb/ nocase ascii wide
                        $string16_NetRipper_offensive_tool_keyword = /\\NetRipper\.sln/ nocase ascii wide
                        $string17_NetRipper_offensive_tool_keyword = /\\NetRipper\.x64\.exe/ nocase ascii wide
                        $string18_NetRipper_offensive_tool_keyword = /\\NetRipper\.x64\.pdb/ nocase ascii wide
                        $string19_NetRipper_offensive_tool_keyword = /\\NetRipper\.x86\.exe/ nocase ascii wide
                        $string20_NetRipper_offensive_tool_keyword = /\\NetRipper\.x86\.pdb/ nocase ascii wide
                        $string21_NetRipper_offensive_tool_keyword = /\\NetRipperLog\.txt/ nocase ascii wide
                        $string22_NetRipper_offensive_tool_keyword = "</NetRipper>" nocase ascii wide
                        $string23_NetRipper_offensive_tool_keyword = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string24_NetRipper_offensive_tool_keyword = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string25_NetRipper_offensive_tool_keyword = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string26_NetRipper_offensive_tool_keyword = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string27_NetRipper_offensive_tool_keyword = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string28_NetRipper_offensive_tool_keyword = "1f4b9fe826113f8139be95e894e033044d0ddd185f9a2f30fcf213852f007790" nocase ascii wide
                        $string29_NetRipper_offensive_tool_keyword = "32201855814f2d6df4a5803a8eb182fe10e401da90fdbf67c2318c523b4fd619" nocase ascii wide
                        $string30_NetRipper_offensive_tool_keyword = "36AB45D2-F886-4803-AA7E-6FD5520458FC" nocase ascii wide
                        $string31_NetRipper_offensive_tool_keyword = "438dbddd65bd3110fe61ebe3266d1cb441ea25dfc13cb626c076203e5721244d" nocase ascii wide
                        $string32_NetRipper_offensive_tool_keyword = "4de892d30281aac34dd5aeb710d6fffc90e46b7d9df8505205531afe991973f4" nocase ascii wide
                        $string33_NetRipper_offensive_tool_keyword = "55d11ca1d51a951627e693d7c26536528c24afd46ea7a1f8bf99907066f62ed4" nocase ascii wide
                        $string34_NetRipper_offensive_tool_keyword = "60BBE2CB-585B-4DBD-9CB9-22F00D3F11E5" nocase ascii wide
                        $string35_NetRipper_offensive_tool_keyword = "8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABl4ZX1IYD7piGA" nocase ascii wide
                        $string36_NetRipper_offensive_tool_keyword = "9a8e6eed94ace0f4d3b91c7a8eb44625aaeb777c757cb262b22591c0f6253449" nocase ascii wide
                        $string37_NetRipper_offensive_tool_keyword = "becb807e8d5a4508b1ea3e4e8ab5af60fd5dcfc4e938a58c1694cc968aab521a" nocase ascii wide
                        $string38_NetRipper_offensive_tool_keyword = "c3e1e5a3e7b7e2d270582b233f94888de48d37642b9a6cdc019d2703aa1e4f0c" nocase ascii wide
                        $string39_NetRipper_offensive_tool_keyword = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string40_NetRipper_offensive_tool_keyword = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string41_NetRipper_offensive_tool_keyword = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string42_NetRipper_offensive_tool_keyword = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string43_NetRipper_offensive_tool_keyword = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string44_NetRipper_offensive_tool_keyword = "Injecting NetRipper into process with ID " nocase ascii wide
                        $string45_NetRipper_offensive_tool_keyword = "Invoke-NetRipper" nocase ascii wide
                        $string46_NetRipper_offensive_tool_keyword = /Invoke\-\-Shellcode\.ps1/ nocase ascii wide
                        $string47_NetRipper_offensive_tool_keyword = "local:Invoke-PatchDll" nocase ascii wide
                        $string48_NetRipper_offensive_tool_keyword = /NetRipper\sDLL\s\(32\sbits\)\ssuccessfully\scompiled/ nocase ascii wide
                        $string49_NetRipper_offensive_tool_keyword = /NetRipper\sDLL\s\(64\sbits\)\ssuccessfully\scompiled/ nocase ascii wide
                        $string50_NetRipper_offensive_tool_keyword = "NytroRST/NetRipper" nocase ascii wide
                        $string51_NetRipper_offensive_tool_keyword = "Patching NetRipper DLL" nocase ascii wide
                        $string52_NetRipper_offensive_tool_keyword = "'S','e','l','f','R','e','f','l','e','c','t','i','v','e'" nocase ascii wide
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