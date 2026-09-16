rule rule_SharPyShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharPyShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharPyShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharPyShell_offensive_tool_keyword = /\sinteract\s\-u\shttp.{0,1000}\:\/\/.{0,1000}\/.{0,1000}\.aspx\s\-p\s/ nocase ascii wide
                        $string2_SharPyShell_offensive_tool_keyword = /\/mimikatz\.py/ nocase ascii wide
                        $string3_SharPyShell_offensive_tool_keyword = /\/net_portscan\.py/ nocase ascii wide
                        $string4_SharPyShell_offensive_tool_keyword = "/SharPyShell" nocase ascii wide
                        $string5_SharPyShell_offensive_tool_keyword = /\/tmp\/revshell\.exe/
                        $string6_SharPyShell_offensive_tool_keyword = /\\inject_shellcode\.py/ nocase ascii wide
                        $string7_SharPyShell_offensive_tool_keyword = /\\JuicyPotato\.pdb/ nocase ascii wide
                        $string8_SharPyShell_offensive_tool_keyword = /\\lateral_wmi\.py/ nocase ascii wide
                        $string9_SharPyShell_offensive_tool_keyword = /\\mimikatz\.py/ nocase ascii wide
                        $string10_SharPyShell_offensive_tool_keyword = /\\net_portscan\.py/ nocase ascii wide
                        $string11_SharPyShell_offensive_tool_keyword = /\\powerkatz\.dll/ nocase ascii wide
                        $string12_SharPyShell_offensive_tool_keyword = /\\Powerup\.ps1/ nocase ascii wide
                        $string13_SharPyShell_offensive_tool_keyword = /\\SharPyShell/ nocase ascii wide
                        $string14_SharPyShell_offensive_tool_keyword = /\\Users\\Public\\revshell\.exe/ nocase ascii wide
                        $string15_SharPyShell_offensive_tool_keyword = /\\whoami_juicy\.txt/ nocase ascii wide
                        $string16_SharPyShell_offensive_tool_keyword = "0e8dfd9cc5fcd99e4ee93d4c015e49dd672ac1813c0270c4ff3ed8c1b9db85d1" nocase ascii wide
                        $string17_SharPyShell_offensive_tool_keyword = "0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036" nocase ascii wide
                        $string18_SharPyShell_offensive_tool_keyword = "3a1081100f285cef3c41c192d3b6d02f3bfcbc2b591be894f12ede8707b436b4" nocase ascii wide
                        $string19_SharPyShell_offensive_tool_keyword = "46c81a0250992cc04c2ee1ce3253fd4629e6ae25da1cecdbfe0427b5aa3157c4" nocase ascii wide
                        $string20_SharPyShell_offensive_tool_keyword = "7f4cb93deb3d53403cc8f23e7d07ad8a8ff7c327ba9362eeb330e5489649da8e" nocase ascii wide
                        $string21_SharPyShell_offensive_tool_keyword = "98d26f3cd9d1e221c76a2b274950d73085f8dd17a2eaceffda43cf5c5a45bdc2" nocase ascii wide
                        $string22_SharPyShell_offensive_tool_keyword = "d1d8362d21a381b0703d4586b73ce78d5332507c62e1d90eb8eb83555db1d6c8" nocase ascii wide
                        $string23_SharPyShell_offensive_tool_keyword = "FJlZi5HZXRGaWVsZCgnYW1zaUluJysnaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUpOw==" nocase ascii wide
                        $string24_SharPyShell_offensive_tool_keyword = /inject_dll_reflective\.py/ nocase ascii wide
                        $string25_SharPyShell_offensive_tool_keyword = /inject_dll_srdi\.py/ nocase ascii wide
                        $string26_SharPyShell_offensive_tool_keyword = /inject_shellcode\.py/ nocase ascii wide
                        $string27_SharPyShell_offensive_tool_keyword = "Injecting converted DLL shellcode into remote process" nocase ascii wide
                        $string28_SharPyShell_offensive_tool_keyword = "Injecting Reflective DLL into remote process" nocase ascii wide
                        $string29_SharPyShell_offensive_tool_keyword = "Invoke-Mimikatz" nocase ascii wide
                        $string30_SharPyShell_offensive_tool_keyword = "JFJlZj1bUmVmXS5Bc3NlbWJseS5HZXRUeXBlKCdTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkFtcycrJ2lVdGlscycpOw==" nocase ascii wide
                        $string31_SharPyShell_offensive_tool_keyword = /JuicyPotato\.exe/ nocase ascii wide
                        $string32_SharPyShell_offensive_tool_keyword = /juicypotato_reflective\.dll/ nocase ascii wide
                        $string33_SharPyShell_offensive_tool_keyword = /lateral_wmi\.py/ nocase ascii wide
                        $string34_SharPyShell_offensive_tool_keyword = /messagebox_reflective\.dll/ nocase ascii wide
                        $string35_SharPyShell_offensive_tool_keyword = /ms16_075_reflection_juicy\.rb/ nocase ascii wide
                        $string36_SharPyShell_offensive_tool_keyword = /net_portscan\s.{0,1000}\/24/ nocase ascii wide
                        $string37_SharPyShell_offensive_tool_keyword = /net_portscan\.py/ nocase ascii wide
                        $string38_SharPyShell_offensive_tool_keyword = "privesc_juicy_potato '" nocase ascii wide
                        $string39_SharPyShell_offensive_tool_keyword = /privesc_juicy_potato\.py/ nocase ascii wide
                        $string40_SharPyShell_offensive_tool_keyword = "privesc_powerup '" nocase ascii wide
                        $string41_SharPyShell_offensive_tool_keyword = /privesc_powerup\.py/ nocase ascii wide
                        $string42_SharPyShell_offensive_tool_keyword = /reverse_shell_https\.ps1/ nocase ascii wide
                        $string43_SharPyShell_offensive_tool_keyword = "SharPyShell Helper Commands:" nocase ascii wide
                        $string44_SharPyShell_offensive_tool_keyword = "SharPyShell" nocase ascii wide
                        $string45_SharPyShell_offensive_tool_keyword = /sharpyshell\.aspx/ nocase ascii wide
                        $string46_SharPyShell_offensive_tool_keyword = /SharPyShell\.py/ nocase ascii wide
                        $string47_SharPyShell_offensive_tool_keyword = /SharPyShell_Test\.ps1/ nocase ascii wide
                        $string48_SharPyShell_offensive_tool_keyword = /SharPyShellPrompt\.py/ nocase ascii wide
                        $string49_SharPyShell_offensive_tool_keyword = /Upload\sit\sto\sthe\starget\sserver\sand\slet\\\\\'s\sstart\shaving\ssome\sfun\s\:\)\s/ nocase ascii wide
                        $string50_SharPyShell_offensive_tool_keyword = /Uploading\sencrypted\sps\smodule\./ nocase ascii wide
                        $string51_SharPyShell_offensive_tool_keyword = "Uploading Juicy Potato binary" nocase ascii wide
                        $string52_SharPyShell_offensive_tool_keyword = "Uploading mimikatz binary" nocase ascii wide

    condition:
        any of them
}