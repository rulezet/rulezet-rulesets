rule Dinjector
{
    meta:
        description = "Detection patterns for the tool 'Dinjector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dinjector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/cradle\.ps1/ nocase ascii wide
                        $string2 = /\/DInjector\.git/ nocase ascii wide
                        $string3 = /\/pid\:1337\s.{0,1000}\/dll\:/ nocase ascii wide
                        $string4 = /\\cradle\.ps1/ nocase ascii wide
                        $string5 = /\\DInjector\.sln/ nocase ascii wide
                        $string6 = /\\DInjector\\/ nocase ascii wide
                        $string7 = "5086CE01-1032-4CA3-A302-6CFF2A8B64DC" nocase ascii wide
                        $string8 = /creds_hunt\.exe/ nocase ascii wide
                        $string9 = /DInjector\.csproj/ nocase ascii wide
                        $string10 = /DInjector\.Detonator/ nocase ascii wide
                        $string11 = /DInjector\.dll/ nocase ascii wide
                        $string12 = "DInjector/Dinjector" nocase ascii wide
                        $string13 = "Dinjector-main" nocase ascii wide
                        $string14 = /encrypt\.py\s.{0,1000}\.bin\s\-p\s.{0,1000}\s\-o\s.{0,1000}\.enc/ nocase ascii wide
                        $string15 = "--entrypoint Dinjector" nocase ascii wide
                        $string16 = /http\:\/\/10\.10\.13\.37/ nocase ascii wide
                        $string17 = /KeeFarceReborn\./ nocase ascii wide
                        $string18 = "Metro-Holografix/Dinjector" nocase ascii wide
                        $string19 = "NtCreateUserProcessShellcode" nocase ascii wide
                        $string20 = /PIC\-Exec.{0,1000}runshellcode\.asm/ nocase ascii wide
                        $string21 = /PIC\-Exec\\addresshunter/ nocase ascii wide
                        $string22 = "win-x64-DynamicKernelWinExecCalc" nocase ascii wide
                        $string23 = "x64win-DynamicNoNull-WinExec-PopCalc-Shellcode" nocase ascii wide

    condition:
        any of them
}