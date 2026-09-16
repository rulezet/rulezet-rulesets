rule rule_C2_related_tools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'C2 related tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2 related tools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_C2_related_tools_offensive_tool_keyword = /\sbeacon64\.bin\s/ nocase ascii wide
                        $string2_C2_related_tools_offensive_tool_keyword = /\sNoPowerShell\./ nocase ascii wide
                        $string3_C2_related_tools_offensive_tool_keyword = /\s\-pe\-exp\-list\s.{0,100}\.dll/ nocase ascii wide
                        $string4_C2_related_tools_offensive_tool_keyword = /\ssigflip\./ nocase ascii wide
                        $string5_C2_related_tools_offensive_tool_keyword = " -U msf -P msf " nocase ascii wide
                        $string6_C2_related_tools_offensive_tool_keyword = /\!wPkgPath\!.{0,100}\!ak\!/ nocase ascii wide
                        $string7_C2_related_tools_offensive_tool_keyword = "/bypass_mod/loader" nocase ascii wide
                        $string8_C2_related_tools_offensive_tool_keyword = "/Cooolis-ms/" nocase ascii wide
                        $string9_C2_related_tools_offensive_tool_keyword = /\/DllExport\.bat/ nocase ascii wide
                        $string10_C2_related_tools_offensive_tool_keyword = "/nopowershell/" nocase ascii wide
                        $string11_C2_related_tools_offensive_tool_keyword = "/ShellcodeFluctuation" nocase ascii wide
                        $string12_C2_related_tools_offensive_tool_keyword = /\/SigFlip\./ nocase ascii wide
                        $string13_C2_related_tools_offensive_tool_keyword = "/SigFlip/" nocase ascii wide
                        $string14_C2_related_tools_offensive_tool_keyword = "/SigLoader/" nocase ascii wide
                        $string15_C2_related_tools_offensive_tool_keyword = "/unhook-bof" nocase ascii wide
                        $string16_C2_related_tools_offensive_tool_keyword = /\\codeloader\.exe/ nocase ascii wide
                        $string17_C2_related_tools_offensive_tool_keyword = /\\Cooolis\-ms\-Loader\\/ nocase ascii wide
                        $string18_C2_related_tools_offensive_tool_keyword = /\\DllExport\.bat/ nocase ascii wide
                        $string19_C2_related_tools_offensive_tool_keyword = /\\NoPowerShell\./ nocase ascii wide
                        $string20_C2_related_tools_offensive_tool_keyword = /\\tests\\beacon64\.bin/ nocase ascii wide
                        $string21_C2_related_tools_offensive_tool_keyword = /APC_Ijnect_Load\.nim/ nocase ascii wide
                        $string22_C2_related_tools_offensive_tool_keyword = /BOFNET\.dll/ nocase ascii wide
                        $string23_C2_related_tools_offensive_tool_keyword = /bofnet_execute\./ nocase ascii wide
                        $string24_C2_related_tools_offensive_tool_keyword = "bWV0YXNwbG9pdA==" nocase ascii wide
                        $string25_C2_related_tools_offensive_tool_keyword = "c2hlbGxjb2Rl" nocase ascii wide
                        $string26_C2_related_tools_offensive_tool_keyword = "cGlwZW5hbWU9" nocase ascii wide
                        $string27_C2_related_tools_offensive_tool_keyword = "cmVmbGVjdGl2ZQ==" nocase ascii wide
                        $string28_C2_related_tools_offensive_tool_keyword = /codeLoader\/codeLoader\./ nocase ascii wide
                        $string29_C2_related_tools_offensive_tool_keyword = /cool.{0,100}\/cool\.zip/ nocase ascii wide
                        $string30_C2_related_tools_offensive_tool_keyword = /coolv0\.1\.exe/ nocase ascii wide
                        $string31_C2_related_tools_offensive_tool_keyword = /Cooolis.{0,100}shellcode/ nocase ascii wide
                        $string32_C2_related_tools_offensive_tool_keyword = "CooolisAdjustTokenPrivileges" nocase ascii wide
                        $string33_C2_related_tools_offensive_tool_keyword = "CooolisCreateRemoteThread" nocase ascii wide
                        $string34_C2_related_tools_offensive_tool_keyword = "Cooolis-ExternalC2" nocase ascii wide
                        $string35_C2_related_tools_offensive_tool_keyword = /Cooolis\-ms\.exe/ nocase ascii wide
                        $string36_C2_related_tools_offensive_tool_keyword = "Cooolis-msf" nocase ascii wide
                        $string37_C2_related_tools_offensive_tool_keyword = /Cooolis\-msX64\.zip/ nocase ascii wide
                        $string38_C2_related_tools_offensive_tool_keyword = /Cooolis\-msX86\.zip/ nocase ascii wide
                        $string39_C2_related_tools_offensive_tool_keyword = "Cooolis-Reflective" nocase ascii wide
                        $string40_C2_related_tools_offensive_tool_keyword = "Cooolis-Shellcode" nocase ascii wide
                        $string41_C2_related_tools_offensive_tool_keyword = /Cooolis\-String\./ nocase ascii wide
                        $string42_C2_related_tools_offensive_tool_keyword = "CooolisVirtualAlloc" nocase ascii wide
                        $string43_C2_related_tools_offensive_tool_keyword = "DllExport -" nocase ascii wide
                        $string44_C2_related_tools_offensive_tool_keyword = "Ed1s0nZ/cool/" nocase ascii wide
                        $string45_C2_related_tools_offensive_tool_keyword = /execute\-assembly.{0,100}sigflip/ nocase ascii wide
                        $string46_C2_related_tools_offensive_tool_keyword = /g_hookedSleep\./ nocase ascii wide
                        $string47_C2_related_tools_offensive_tool_keyword = "GetWhoamiCommand" nocase ascii wide
                        $string48_C2_related_tools_offensive_tool_keyword = "IERMTCBpbnRvIHByb2Nlc3MgOiA=" nocase ascii wide
                        $string49_C2_related_tools_offensive_tool_keyword = "initializeShellcodeFluctuation" nocase ascii wide
                        $string50_C2_related_tools_offensive_tool_keyword = "injectShellcode" nocase ascii wide
                        $string51_C2_related_tools_offensive_tool_keyword = "isShellcodeThread" nocase ascii wide
                        $string52_C2_related_tools_offensive_tool_keyword = "LUgsLS1IT1NU" nocase ascii wide
                        $string53_C2_related_tools_offensive_tool_keyword = "LVAsLS1QT1JU" nocase ascii wide
                        $string54_C2_related_tools_offensive_tool_keyword = "LW8sLS1vcHRpb25z" nocase ascii wide
                        $string55_C2_related_tools_offensive_tool_keyword = "LWIsLS1idWNrZXQ=" nocase ascii wide
                        $string56_C2_related_tools_offensive_tool_keyword = "LWYsLS1maWxl" nocase ascii wide
                        $string57_C2_related_tools_offensive_tool_keyword = "LXAsLS1waWQ=" nocase ascii wide
                        $string58_C2_related_tools_offensive_tool_keyword = "LXAsLS1wYXlsb2Fk" nocase ascii wide
                        $string59_C2_related_tools_offensive_tool_keyword = "LXUsLS11cmk=" nocase ascii wide
                        $string60_C2_related_tools_offensive_tool_keyword = "med0x2e/SigFlip" nocase ascii wide
                        $string61_C2_related_tools_offensive_tool_keyword = "NimShellCodeLoader" nocase ascii wide
                        $string62_C2_related_tools_offensive_tool_keyword = /NoPowerShell\.cna/ nocase ascii wide
                        $string63_C2_related_tools_offensive_tool_keyword = /NoPowerShell\.dll/ nocase ascii wide
                        $string64_C2_related_tools_offensive_tool_keyword = /nopowershell\.exe/ nocase ascii wide
                        $string65_C2_related_tools_offensive_tool_keyword = /NoPowerShell\/.{0,100}\.cs/ nocase ascii wide
                        $string66_C2_related_tools_offensive_tool_keyword = "nps whoami" nocase ascii wide
                        $string67_C2_related_tools_offensive_tool_keyword = "OEP_Hiijack_Inject_Load" nocase ascii wide
                        $string68_C2_related_tools_offensive_tool_keyword = "Q29iYWx0IFN0cmlrZSBFeHRlcm5hbCBDMiBMb2FkZXI=" nocase ascii wide
                        $string69_C2_related_tools_offensive_tool_keyword = "readShellcode" nocase ascii wide
                        $string70_C2_related_tools_offensive_tool_keyword = "runShellcode" nocase ascii wide
                        $string71_C2_related_tools_offensive_tool_keyword = "Rvn0xsy/Cooolis-ms" nocase ascii wide
                        $string72_C2_related_tools_offensive_tool_keyword = "RXh0ZXJuYWwgQzIgUG9ydA==" nocase ascii wide
                        $string73_C2_related_tools_offensive_tool_keyword = "service/executable/" nocase ascii wide
                        $string74_C2_related_tools_offensive_tool_keyword = /service\/executable\/compile\.exe/ nocase ascii wide
                        $string75_C2_related_tools_offensive_tool_keyword = "shellcodeEncryptDecrypt" nocase ascii wide
                        $string76_C2_related_tools_offensive_tool_keyword = /ShellcodeFluctuation\./ nocase ascii wide
                        $string77_C2_related_tools_offensive_tool_keyword = "ShellcodeFluctuation64" nocase ascii wide
                        $string78_C2_related_tools_offensive_tool_keyword = "ShellcodeFluctuation86" nocase ascii wide
                        $string79_C2_related_tools_offensive_tool_keyword = /sigflip.{0,100}\/Bof\// nocase ascii wide
                        $string80_C2_related_tools_offensive_tool_keyword = "SigInject " nocase ascii wide
                        $string81_C2_related_tools_offensive_tool_keyword = "SigLoader " nocase ascii wide
                        $string82_C2_related_tools_offensive_tool_keyword = /SigLoader\./ nocase ascii wide
                        $string83_C2_related_tools_offensive_tool_keyword = /src\\unhook\.c/ nocase ascii wide
                        $string84_C2_related_tools_offensive_tool_keyword = /Thread_Hiijack_Inject_Load\./ nocase ascii wide
                        $string85_C2_related_tools_offensive_tool_keyword = "ThreadStackSpoofer" nocase ascii wide
                        $string86_C2_related_tools_offensive_tool_keyword = "TWV0YXNwbG9pdCBSUEMgTG9hZGVy" nocase ascii wide
                        $string87_C2_related_tools_offensive_tool_keyword = "U2hlbGxjb2RlIFBhdGg=" nocase ascii wide
                        $string88_C2_related_tools_offensive_tool_keyword = "UFR5cGUgQW5kIFBPcHRpb25zIFRvbyBsb25nIQ==" nocase ascii wide
                        $string89_C2_related_tools_offensive_tool_keyword = "UGF5bG9hZCBOYW1lLCBlLmcuIHdpbmRvd3MvbWV0ZXJwcmV0ZXIvcmV2ZXJzZV90Y3A=" nocase ascii wide
                        $string90_C2_related_tools_offensive_tool_keyword = "UGF5bG9hZCBvcHRpb25zLCBlLmcuIExIT1NUPTEuMS4xLjEsTFBPUlQ9ODg2Ng==" nocase ascii wide
                        $string91_C2_related_tools_offensive_tool_keyword = "UlBDIFNlcnZlciBIb3N0" nocase ascii wide
                        $string92_C2_related_tools_offensive_tool_keyword = "UlBDIFNlcnZlciBQb3J0" nocase ascii wide
                        $string93_C2_related_tools_offensive_tool_keyword = "UmVmbGVjdGl2ZSBETEwgaW5qZWN0aW9u" nocase ascii wide
                        $string94_C2_related_tools_offensive_tool_keyword = "UmVmbGVjdGl2ZSBETEwgT1NTIEJ1Y2tldA==" nocase ascii wide
                        $string95_C2_related_tools_offensive_tool_keyword = "UmVmbGVjdGl2ZSBETEwgUGF0aA==" nocase ascii wide
                        $string96_C2_related_tools_offensive_tool_keyword = "UmVmbGVjdGl2ZSBETEwgVVJJ" nocase ascii wide
                        $string97_C2_related_tools_offensive_tool_keyword = "UmVmbGVjdGl2ZSBJbmplY3QgUHJvY2VzcyBJZA==" nocase ascii wide
                        $string98_C2_related_tools_offensive_tool_keyword = "unhook kernel32" nocase ascii wide
                        $string99_C2_related_tools_offensive_tool_keyword = "unhook wldp amsi" nocase ascii wide
                        $string100_C2_related_tools_offensive_tool_keyword = "WypdIENhbid0IENvbm5lY3QgQWxpeXVuIEJ1Y2tldC4=" nocase ascii wide
                        $string101_C2_related_tools_offensive_tool_keyword = "WypdIFRoZSBCdWNrZXQgb3IgUmVmbGVjdGl2ZSBETEwgVVJJIGlzIEVtcHR5Lg==" nocase ascii wide
                        $string102_C2_related_tools_offensive_tool_keyword = "WytdIEluamVjdGVkIHRoZSA=" nocase ascii wide
                        $string103_C2_related_tools_offensive_tool_keyword = "Y29iYWx0c3RyaWtl" nocase ascii wide
                        $string104_C2_related_tools_offensive_tool_keyword = "YmxvY2s9MTAw" nocase ascii wide
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