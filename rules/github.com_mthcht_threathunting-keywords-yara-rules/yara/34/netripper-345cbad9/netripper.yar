rule NetRipper
{
    meta:
        description = "Detection patterns for the tool 'NetRipper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetRipper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sNetRipper\.dll/ nocase ascii wide
                        $string2 = /\.DLL\sinjection\scomplete\!/ nocase ascii wide
                        $string3 = /\.exe\s\-w\s.{0,100}\.dll\s\-l\sTEMP\s\-p\strue\s\-d\s4096\s\-s\suser\,pass/ nocase ascii wide
                        $string4 = /\/NetRipper\.dll/ nocase ascii wide
                        $string5 = /\/NetRipper\.exe/ nocase ascii wide
                        $string6 = /\/NetRipper\.git/ nocase ascii wide
                        $string7 = /\/NetRipper\.x64\.exe/ nocase ascii wide
                        $string8 = /\/NetRipper\.x86\.exe/ nocase ascii wide
                        $string9 = /\/NetRipperLog\.txt/
                        $string10 = "/windows/gather/netripper" nocase ascii wide
                        $string11 = /\\InjectedDLL\.cpp/ nocase ascii wide
                        $string12 = /\\NetRipper\.cpp/ nocase ascii wide
                        $string13 = /\\NetRipper\.dll/ nocase ascii wide
                        $string14 = /\\NetRipper\.exe/ nocase ascii wide
                        $string15 = /\\netripper\.rb/ nocase ascii wide
                        $string16 = /\\NetRipper\.sln/ nocase ascii wide
                        $string17 = /\\NetRipper\.x64\.exe/ nocase ascii wide
                        $string18 = /\\NetRipper\.x64\.pdb/ nocase ascii wide
                        $string19 = /\\NetRipper\.x86\.exe/ nocase ascii wide
                        $string20 = /\\NetRipper\.x86\.pdb/ nocase ascii wide
                        $string21 = /\\NetRipperLog\.txt/ nocase ascii wide
                        $string22 = "</NetRipper>" nocase ascii wide
                        $string23 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string24 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string25 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string26 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string27 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase ascii wide
                        $string28 = "1f4b9fe826113f8139be95e894e033044d0ddd185f9a2f30fcf213852f007790" nocase ascii wide
                        $string29 = "32201855814f2d6df4a5803a8eb182fe10e401da90fdbf67c2318c523b4fd619" nocase ascii wide
                        $string30 = "36AB45D2-F886-4803-AA7E-6FD5520458FC" nocase ascii wide
                        $string31 = "438dbddd65bd3110fe61ebe3266d1cb441ea25dfc13cb626c076203e5721244d" nocase ascii wide
                        $string32 = "4de892d30281aac34dd5aeb710d6fffc90e46b7d9df8505205531afe991973f4" nocase ascii wide
                        $string33 = "55d11ca1d51a951627e693d7c26536528c24afd46ea7a1f8bf99907066f62ed4" nocase ascii wide
                        $string34 = "60BBE2CB-585B-4DBD-9CB9-22F00D3F11E5" nocase ascii wide
                        $string35 = "8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABl4ZX1IYD7piGA" nocase ascii wide
                        $string36 = "9a8e6eed94ace0f4d3b91c7a8eb44625aaeb777c757cb262b22591c0f6253449" nocase ascii wide
                        $string37 = "becb807e8d5a4508b1ea3e4e8ab5af60fd5dcfc4e938a58c1694cc968aab521a" nocase ascii wide
                        $string38 = "c3e1e5a3e7b7e2d270582b233f94888de48d37642b9a6cdc019d2703aa1e4f0c" nocase ascii wide
                        $string39 = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string40 = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string41 = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string42 = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string43 = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase ascii wide
                        $string44 = "Injecting NetRipper into process with ID " nocase ascii wide
                        $string45 = "Invoke-NetRipper" nocase ascii wide
                        $string46 = /Invoke\-\-Shellcode\.ps1/ nocase ascii wide
                        $string47 = "local:Invoke-PatchDll" nocase ascii wide
                        $string48 = /NetRipper\sDLL\s\(32\sbits\)\ssuccessfully\scompiled/ nocase ascii wide
                        $string49 = /NetRipper\sDLL\s\(64\sbits\)\ssuccessfully\scompiled/ nocase ascii wide
                        $string50 = "NytroRST/NetRipper" nocase ascii wide
                        $string51 = "Patching NetRipper DLL" nocase ascii wide
                        $string52 = "'S','e','l','f','R','e','f','l','e','c','t','i','v','e'" nocase ascii wide
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