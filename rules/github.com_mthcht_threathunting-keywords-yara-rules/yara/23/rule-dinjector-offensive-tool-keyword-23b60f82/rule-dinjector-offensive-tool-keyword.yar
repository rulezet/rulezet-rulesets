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
                        $string3_Dinjector_offensive_tool_keyword = /\/pid\:1337\s.{0,1000}\/dll\:/ nocase ascii wide
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
                        $string14_Dinjector_offensive_tool_keyword = /encrypt\.py\s.{0,1000}\.bin\s\-p\s.{0,1000}\s\-o\s.{0,1000}\.enc/ nocase ascii wide
                        $string15_Dinjector_offensive_tool_keyword = "--entrypoint Dinjector" nocase ascii wide
                        $string16_Dinjector_offensive_tool_keyword = /http\:\/\/10\.10\.13\.37/ nocase ascii wide
                        $string17_Dinjector_offensive_tool_keyword = /KeeFarceReborn\./ nocase ascii wide
                        $string18_Dinjector_offensive_tool_keyword = "Metro-Holografix/Dinjector" nocase ascii wide
                        $string19_Dinjector_offensive_tool_keyword = "NtCreateUserProcessShellcode" nocase ascii wide
                        $string20_Dinjector_offensive_tool_keyword = /PIC\-Exec.{0,1000}runshellcode\.asm/ nocase ascii wide
                        $string21_Dinjector_offensive_tool_keyword = /PIC\-Exec\\addresshunter/ nocase ascii wide
                        $string22_Dinjector_offensive_tool_keyword = "win-x64-DynamicKernelWinExecCalc" nocase ascii wide
                        $string23_Dinjector_offensive_tool_keyword = "x64win-DynamicNoNull-WinExec-PopCalc-Shellcode" nocase ascii wide

    condition:
        any of them
}