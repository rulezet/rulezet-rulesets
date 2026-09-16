rule rule_Dinjector_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Dinjector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dinjector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Dinjector_offensive_tool_keyword = /\/cradle\.ps1/ nocase ascii wide
                        $string2_Dinjector_offensive_tool_keyword = /\/DInjector\.git/ nocase ascii wide
                        $string3_Dinjector_offensive_tool_keyword = /\/pid\:1337\s.{0,100}\/dll\:/ nocase ascii wide
                        $string4_Dinjector_offensive_tool_keyword = /\\cradle\.ps1/ nocase ascii wide
                        $string5_Dinjector_offensive_tool_keyword = /\\DInjector\.sln/ nocase ascii wide
                        $string6_Dinjector_offensive_tool_keyword = /\\DInjector\\/ nocase ascii wide
                        $string7_Dinjector_offensive_tool_keyword = "5086CE01-1032-4CA3-A302-6CFF2A8B64DC" nocase ascii wide
                        $string8_Dinjector_offensive_tool_keyword = /creds_hunt\.exe/ nocase ascii wide
                        $string9_Dinjector_offensive_tool_keyword = /DInjector\.csproj/ nocase ascii wide
                        $string10_Dinjector_offensive_tool_keyword = /DInjector\.Detonator/ nocase ascii wide
                        $string11_Dinjector_offensive_tool_keyword = /DInjector\.dll/ nocase ascii wide
                        $string12_Dinjector_offensive_tool_keyword = "DInjector/Dinjector" nocase ascii wide
                        $string13_Dinjector_offensive_tool_keyword = "Dinjector-main" nocase ascii wide
                        $string14_Dinjector_offensive_tool_keyword = /encrypt\.py\s.{0,100}\.bin\s\-p\s.{0,100}\s\-o\s.{0,100}\.enc/ nocase ascii wide
                        $string15_Dinjector_offensive_tool_keyword = "--entrypoint Dinjector" nocase ascii wide
                        $string16_Dinjector_offensive_tool_keyword = /http\:\/\/10\.10\.13\.37/ nocase ascii wide
                        $string17_Dinjector_offensive_tool_keyword = /KeeFarceReborn\./ nocase ascii wide
                        $string18_Dinjector_offensive_tool_keyword = "Metro-Holografix/Dinjector" nocase ascii wide
                        $string19_Dinjector_offensive_tool_keyword = "NtCreateUserProcessShellcode" nocase ascii wide
                        $string20_Dinjector_offensive_tool_keyword = /PIC\-Exec.{0,100}runshellcode\.asm/ nocase ascii wide
                        $string21_Dinjector_offensive_tool_keyword = /PIC\-Exec\\addresshunter/ nocase ascii wide
                        $string22_Dinjector_offensive_tool_keyword = "win-x64-DynamicKernelWinExecCalc" nocase ascii wide
                        $string23_Dinjector_offensive_tool_keyword = "x64win-DynamicNoNull-WinExec-PopCalc-Shellcode" nocase ascii wide
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