rule SharPyShell
{
    meta:
        description = "Detection patterns for the tool 'SharPyShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharPyShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sinteract\s\-u\shttp.{0,1000}\:\/\/.{0,1000}\/.{0,1000}\.aspx\s\-p\s/ nocase ascii wide
                        $string2 = /\/mimikatz\.py/ nocase ascii wide
                        $string3 = /\/net_portscan\.py/ nocase ascii wide
                        $string4 = "/SharPyShell" nocase ascii wide
                        $string5 = /\/tmp\/revshell\.exe/
                        $string6 = /\\inject_shellcode\.py/ nocase ascii wide
                        $string7 = /\\JuicyPotato\.pdb/ nocase ascii wide
                        $string8 = /\\lateral_wmi\.py/ nocase ascii wide
                        $string9 = /\\mimikatz\.py/ nocase ascii wide
                        $string10 = /\\net_portscan\.py/ nocase ascii wide
                        $string11 = /\\powerkatz\.dll/ nocase ascii wide
                        $string12 = /\\Powerup\.ps1/ nocase ascii wide
                        $string13 = /\\SharPyShell/ nocase ascii wide
                        $string14 = /\\Users\\Public\\revshell\.exe/ nocase ascii wide
                        $string15 = /\\whoami_juicy\.txt/ nocase ascii wide
                        $string16 = "0e8dfd9cc5fcd99e4ee93d4c015e49dd672ac1813c0270c4ff3ed8c1b9db85d1" nocase ascii wide
                        $string17 = "0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036" nocase ascii wide
                        $string18 = "3a1081100f285cef3c41c192d3b6d02f3bfcbc2b591be894f12ede8707b436b4" nocase ascii wide
                        $string19 = "46c81a0250992cc04c2ee1ce3253fd4629e6ae25da1cecdbfe0427b5aa3157c4" nocase ascii wide
                        $string20 = "7f4cb93deb3d53403cc8f23e7d07ad8a8ff7c327ba9362eeb330e5489649da8e" nocase ascii wide
                        $string21 = "98d26f3cd9d1e221c76a2b274950d73085f8dd17a2eaceffda43cf5c5a45bdc2" nocase ascii wide
                        $string22 = "d1d8362d21a381b0703d4586b73ce78d5332507c62e1d90eb8eb83555db1d6c8" nocase ascii wide
                        $string23 = "FJlZi5HZXRGaWVsZCgnYW1zaUluJysnaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUpOw==" nocase ascii wide
                        $string24 = /inject_dll_reflective\.py/ nocase ascii wide
                        $string25 = /inject_dll_srdi\.py/ nocase ascii wide
                        $string26 = /inject_shellcode\.py/ nocase ascii wide
                        $string27 = "Injecting converted DLL shellcode into remote process" nocase ascii wide
                        $string28 = "Injecting Reflective DLL into remote process" nocase ascii wide
                        $string29 = "Invoke-Mimikatz" nocase ascii wide
                        $string30 = "JFJlZj1bUmVmXS5Bc3NlbWJseS5HZXRUeXBlKCdTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkFtcycrJ2lVdGlscycpOw==" nocase ascii wide
                        $string31 = /JuicyPotato\.exe/ nocase ascii wide
                        $string32 = /juicypotato_reflective\.dll/ nocase ascii wide
                        $string33 = /lateral_wmi\.py/ nocase ascii wide
                        $string34 = /messagebox_reflective\.dll/ nocase ascii wide
                        $string35 = /ms16_075_reflection_juicy\.rb/ nocase ascii wide
                        $string36 = /net_portscan\s.{0,1000}\/24/ nocase ascii wide
                        $string37 = /net_portscan\.py/ nocase ascii wide
                        $string38 = "privesc_juicy_potato '" nocase ascii wide
                        $string39 = /privesc_juicy_potato\.py/ nocase ascii wide
                        $string40 = "privesc_powerup '" nocase ascii wide
                        $string41 = /privesc_powerup\.py/ nocase ascii wide
                        $string42 = /reverse_shell_https\.ps1/ nocase ascii wide
                        $string43 = "SharPyShell Helper Commands:" nocase ascii wide
                        $string44 = "SharPyShell" nocase ascii wide
                        $string45 = /sharpyshell\.aspx/ nocase ascii wide
                        $string46 = /SharPyShell\.py/ nocase ascii wide
                        $string47 = /SharPyShell_Test\.ps1/ nocase ascii wide
                        $string48 = /SharPyShellPrompt\.py/ nocase ascii wide
                        $string49 = /Upload\sit\sto\sthe\starget\sserver\sand\slet\\\\\'s\sstart\shaving\ssome\sfun\s\:\)\s/ nocase ascii wide
                        $string50 = /Uploading\sencrypted\sps\smodule\./ nocase ascii wide
                        $string51 = "Uploading Juicy Potato binary" nocase ascii wide
                        $string52 = "Uploading mimikatz binary" nocase ascii wide

    condition:
        any of them
}