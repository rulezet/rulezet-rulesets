rule rule_Pezor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pezor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pezor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Pezor_offensive_tool_keyword = " -64 -format=bof " nocase ascii wide
                        $string2_Pezor_offensive_tool_keyword = " -64 -format=dll " nocase ascii wide
                        $string3_Pezor_offensive_tool_keyword = " -64 -format=service-dll " nocase ascii wide
                        $string4_Pezor_offensive_tool_keyword = " -fluctuate=NA -sleep=" nocase ascii wide
                        $string5_Pezor_offensive_tool_keyword = " -fluctuate=RW -sleep=" nocase ascii wide
                        $string6_Pezor_offensive_tool_keyword = /\s\-format\=bof\s.{0,1000}\.exe/ nocase ascii wide
                        $string7_Pezor_offensive_tool_keyword = " -format=bof -cleanup " nocase ascii wide
                        $string8_Pezor_offensive_tool_keyword = " -format=dotnet -sleep=" nocase ascii wide
                        $string9_Pezor_offensive_tool_keyword = " -format=dotnet-pinvoke " nocase ascii wide
                        $string10_Pezor_offensive_tool_keyword = /\s\-format\=dotnet\-pinvoke\s.{0,1000}\.exe/ nocase ascii wide
                        $string11_Pezor_offensive_tool_keyword = " -format=reflective-dll " nocase ascii wide
                        $string12_Pezor_offensive_tool_keyword = /\s\-format\=reflective\-dll\s.{0,1000}\.exe/ nocase ascii wide
                        $string13_Pezor_offensive_tool_keyword = /\s\-format\=service\-dll\s.{0,1000}\.exe/ nocase ascii wide
                        $string14_Pezor_offensive_tool_keyword = /\s\-format\=service\-exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string15_Pezor_offensive_tool_keyword = " kalilinux/kali-rolling"
                        $string16_Pezor_offensive_tool_keyword = /\s\-p\s.{0,1000}\\mimi\.out/ nocase ascii wide
                        $string17_Pezor_offensive_tool_keyword = /\sPEzor\.py\s/ nocase ascii wide
                        $string18_Pezor_offensive_tool_keyword = /\sPEzor\.sh\s/
                        $string19_Pezor_offensive_tool_keyword = /\sPEzor\.sh\s/
                        $string20_Pezor_offensive_tool_keyword = " -sgn -syscalls " nocase ascii wide
                        $string21_Pezor_offensive_tool_keyword = " -sgn -unhook -antidebug " nocase ascii wide
                        $string22_Pezor_offensive_tool_keyword = /\s\-syscalls\s\-sleep\=.{0,1000}\.exe/ nocase ascii wide
                        $string23_Pezor_offensive_tool_keyword = " -unhook -antidebug " nocase ascii wide
                        $string24_Pezor_offensive_tool_keyword = /\s\-unhook\s\-antidebug\s.{0,1000}\s\-self\s\-sleep/ nocase ascii wide
                        $string25_Pezor_offensive_tool_keyword = " -unhook -syscalls -obfuscate " nocase ascii wide
                        $string26_Pezor_offensive_tool_keyword = /\.\/PEzor\.sh/
                        $string27_Pezor_offensive_tool_keyword = /\.sh\s\-format\=bof\s.{0,1000}\.exe/
                        $string28_Pezor_offensive_tool_keyword = /\.sh\s\-format\=service\-dll\s/
                        $string29_Pezor_offensive_tool_keyword = /\.sh\s\-format\=service\-exe\s/
                        $string30_Pezor_offensive_tool_keyword = /\.sh\s\-xorkey\=/
                        $string31_Pezor_offensive_tool_keyword = /\/bof\.cpp\s/
                        $string32_Pezor_offensive_tool_keyword = /\/inject\.cpp/ nocase ascii wide
                        $string33_Pezor_offensive_tool_keyword = /\/inline_syscall\.git/ nocase ascii wide
                        $string34_Pezor_offensive_tool_keyword = /\/inline_syscall\/include\/in_memory_init\.hpp/ nocase ascii wide
                        $string35_Pezor_offensive_tool_keyword = /\/PEzor\.cna/ nocase ascii wide
                        $string36_Pezor_offensive_tool_keyword = /\/PEzor\.git/ nocase ascii wide
                        $string37_Pezor_offensive_tool_keyword = /\/PEzor\.git/ nocase ascii wide
                        $string38_Pezor_offensive_tool_keyword = /\/PEzor\.py/
                        $string39_Pezor_offensive_tool_keyword = /\/PEzor\.sh\s/
                        $string40_Pezor_offensive_tool_keyword = /\/PEzor\/inject\.cpp/ nocase ascii wide
                        $string41_Pezor_offensive_tool_keyword = /\/ReflectiveDll\.c/ nocase ascii wide
                        $string42_Pezor_offensive_tool_keyword = "/ReflectiveDLLInjection/" nocase ascii wide
                        $string43_Pezor_offensive_tool_keyword = /\/ReflectiveLoader\.c/ nocase ascii wide
                        $string44_Pezor_offensive_tool_keyword = /\/shellcode\.bin\./ nocase ascii wide
                        $string45_Pezor_offensive_tool_keyword = /\/shellcode\.hpp/ nocase ascii wide
                        $string46_Pezor_offensive_tool_keyword = /\/system\:SystemBkup\.hiv\s\/sam\:SamBkup\.hiv/
                        $string47_Pezor_offensive_tool_keyword = /\[PEzor\]\scleanup\scomplete/ nocase ascii wide
                        $string48_Pezor_offensive_tool_keyword = /\[PEzor\]\spayload\sfreed/ nocase ascii wide
                        $string49_Pezor_offensive_tool_keyword = /\[PEzor\]\sstarting\sBOF/ nocase ascii wide
                        $string50_Pezor_offensive_tool_keyword = /\\dll\-sideload\\main\.cpp/ nocase ascii wide
                        $string51_Pezor_offensive_tool_keyword = /\\PEzor\.cpp/ nocase ascii wide
                        $string52_Pezor_offensive_tool_keyword = /\\PEzor\.hpp/ nocase ascii wide
                        $string53_Pezor_offensive_tool_keyword = /\\PEzor\\loader\.c/ nocase ascii wide
                        $string54_Pezor_offensive_tool_keyword = /\\shellcode\.hpp/ nocase ascii wide
                        $string55_Pezor_offensive_tool_keyword = "_prefix_PEzor_" nocase ascii wide
                        $string56_Pezor_offensive_tool_keyword = "_REFLECTIVEDLLINJECTION_" nocase ascii wide
                        $string57_Pezor_offensive_tool_keyword = "-64 -format=reflective-dll " nocase ascii wide
                        $string58_Pezor_offensive_tool_keyword = "cannot encode the shellcode when self-executing the payload" nocase ascii wide
                        $string59_Pezor_offensive_tool_keyword = /Console\.WriteLine.{0,1000}self\sexecuting\sthe\spayload/ nocase ascii wide
                        $string60_Pezor_offensive_tool_keyword = "cowsay -f dragon 'PEzor!!" nocase ascii wide
                        $string61_Pezor_offensive_tool_keyword = /\-dll\-sideload\=.{0,1000}\.dll/ nocase ascii wide
                        $string62_Pezor_offensive_tool_keyword = "echo 'PEzor!!" nocase ascii wide
                        $string63_Pezor_offensive_tool_keyword = "execute_Pezor" nocase ascii wide
                        $string64_Pezor_offensive_tool_keyword = "execute-Pezor" nocase ascii wide
                        $string65_Pezor_offensive_tool_keyword = "-format=dotnet-createsection -sleep" nocase ascii wide
                        $string66_Pezor_offensive_tool_keyword = "generate_raw_payload" nocase ascii wide
                        $string67_Pezor_offensive_tool_keyword = "inject_shellcode_self" nocase ascii wide
                        $string68_Pezor_offensive_tool_keyword = /iwantmore\.pizza\/posts\/PEzor\.html/ nocase ascii wide
                        $string69_Pezor_offensive_tool_keyword = "PEzor generated Beacon Object File" nocase ascii wide
                        $string70_Pezor_offensive_tool_keyword = "PEzor!! v" nocase ascii wide
                        $string71_Pezor_offensive_tool_keyword = /PEzor.{0,1000}\/Inject\.c/ nocase ascii wide
                        $string72_Pezor_offensive_tool_keyword = /Pezor.{0,1000}inject\.hpp/ nocase ascii wide
                        $string73_Pezor_offensive_tool_keyword = /PEzor\.sh\s\-/
                        $string74_Pezor_offensive_tool_keyword = /PEzor\.sh\s.{0,1000}\.bin/
                        $string75_Pezor_offensive_tool_keyword = /PEzor\.sh\s\-32/
                        $string76_Pezor_offensive_tool_keyword = /PEzor\.sh\s\-64/
                        $string77_Pezor_offensive_tool_keyword = /PEzor\/.{0,1000}\/bof\.cpp/ nocase ascii wide
                        $string78_Pezor_offensive_tool_keyword = /PEzor\/.{0,1000}syscalls\.hpp/ nocase ascii wide
                        $string79_Pezor_offensive_tool_keyword = /PEzor\\inject\.cpp/ nocase ascii wide
                        $string80_Pezor_offensive_tool_keyword = "phra/Pezor" nocase ascii wide
                        $string81_Pezor_offensive_tool_keyword = "phra/Pezor/" nocase ascii wide
                        $string82_Pezor_offensive_tool_keyword = "ReflectiveDLLInjection/dll" nocase ascii wide
                        $string83_Pezor_offensive_tool_keyword = /shellcode\.bin\.donut/ nocase ascii wide

    condition:
        any of them
}