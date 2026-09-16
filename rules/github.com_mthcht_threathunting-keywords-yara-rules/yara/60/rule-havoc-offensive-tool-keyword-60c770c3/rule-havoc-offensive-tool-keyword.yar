rule rule_havoc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'havoc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "havoc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_havoc_offensive_tool_keyword = /\sdemon\.x64\.exe/ nocase ascii wide
                        $string2_havoc_offensive_tool_keyword = " havoc-client" nocase ascii wide
                        $string3_havoc_offensive_tool_keyword = /\.\/donut\s.{0,100}\.exe/
                        $string4_havoc_offensive_tool_keyword = /\.\/Havoc/
                        $string5_havoc_offensive_tool_keyword = /\.\/havoc\s/
                        $string6_havoc_offensive_tool_keyword = "/Cracked5pider/" nocase ascii wide
                        $string7_havoc_offensive_tool_keyword = /\/demon\.x64\.bin/ nocase ascii wide
                        $string8_havoc_offensive_tool_keyword = /\/demon\.x64\.exe/ nocase ascii wide
                        $string9_havoc_offensive_tool_keyword = /\/demon1\.dll/ nocase ascii wide
                        $string10_havoc_offensive_tool_keyword = /\/demosyscalls\.exe/ nocase ascii wide
                        $string11_havoc_offensive_tool_keyword = /\/Dialogs\/Payload\.hpp/ nocase ascii wide
                        $string12_havoc_offensive_tool_keyword = /\/Havoc\.cpp/ nocase ascii wide
                        $string13_havoc_offensive_tool_keyword = /\/Havoc\.qss/ nocase ascii wide
                        $string14_havoc_offensive_tool_keyword = /\/Havoc\.rc/ nocase ascii wide
                        $string15_havoc_offensive_tool_keyword = "/Havoc/data/" nocase ascii wide
                        $string16_havoc_offensive_tool_keyword = "/Havoc/main/" nocase ascii wide
                        $string17_havoc_offensive_tool_keyword = "/HavocFramework/" nocase ascii wide
                        $string18_havoc_offensive_tool_keyword = "/HavocImages/" nocase ascii wide
                        $string19_havoc_offensive_tool_keyword = "/havoc-py/" nocase ascii wide
                        $string20_havoc_offensive_tool_keyword = /\/implants\/.{0,100}\/Syscalls\./ nocase ascii wide
                        $string21_havoc_offensive_tool_keyword = "/Jump-exec/Psexec" nocase ascii wide
                        $string22_havoc_offensive_tool_keyword = /\/kerberoast\.c/ nocase ascii wide
                        $string23_havoc_offensive_tool_keyword = /\/kerberoast\.h/ nocase ascii wide
                        $string24_havoc_offensive_tool_keyword = /\/nanodump\./ nocase ascii wide
                        $string25_havoc_offensive_tool_keyword = "/payloads/DllLdr/" nocase ascii wide
                        $string26_havoc_offensive_tool_keyword = /\/RemoteOps\.py/ nocase ascii wide
                        $string27_havoc_offensive_tool_keyword = /\/scshell\.py/ nocase ascii wide
                        $string28_havoc_offensive_tool_keyword = /\/Talon\.py/
                        $string29_havoc_offensive_tool_keyword = /\/Talon\/.{0,100}Agent\/Source/ nocase ascii wide
                        $string30_havoc_offensive_tool_keyword = /\/Widgets\/LootWidget\./ nocase ascii wide
                        $string31_havoc_offensive_tool_keyword = /\/WMI\/wmi\.py/ nocase ascii wide
                        $string32_havoc_offensive_tool_keyword = /\\demon\.dll/ nocase ascii wide
                        $string33_havoc_offensive_tool_keyword = /\\demon\.x64\.bin/ nocase ascii wide
                        $string34_havoc_offensive_tool_keyword = /\\demon\.x64\.exe/ nocase ascii wide
                        $string35_havoc_offensive_tool_keyword = /\\demon1\.dll/ nocase ascii wide
                        $string36_havoc_offensive_tool_keyword = /\\demosyscalls\.exe/ nocase ascii wide
                        $string37_havoc_offensive_tool_keyword = /\\Ekko\.exe/ nocase ascii wide
                        $string38_havoc_offensive_tool_keyword = "40056/service-endpoint" nocase ascii wide
                        $string39_havoc_offensive_tool_keyword = "5spider:password1234" nocase ascii wide
                        $string40_havoc_offensive_tool_keyword = /bin\/addusertogroup\.x64/ nocase ascii wide
                        $string41_havoc_offensive_tool_keyword = /bin\/setuserpass\.x64/ nocase ascii wide
                        $string42_havoc_offensive_tool_keyword = /Delegation\/delegation\.py/ nocase ascii wide
                        $string43_havoc_offensive_tool_keyword = /DllLdr\.x64\.bin/ nocase ascii wide
                        $string44_havoc_offensive_tool_keyword = /Domaininfo\/Domaininfo\.py/ nocase ascii wide
                        $string45_havoc_offensive_tool_keyword = "dotnet inline-execute " nocase ascii wide
                        $string46_havoc_offensive_tool_keyword = /externalc2\.py/ nocase ascii wide
                        $string47_havoc_offensive_tool_keyword = "f5a45c4aa478a7ba9b44654a929bddc2f6453cd8d6f37cd893dda47220ad9870" nocase ascii wide
                        $string48_havoc_offensive_tool_keyword = "havoc client" nocase ascii wide
                        $string49_havoc_offensive_tool_keyword = "havoc server" nocase ascii wide
                        $string50_havoc_offensive_tool_keyword = /havoc\.agent/ nocase ascii wide
                        $string51_havoc_offensive_tool_keyword = /Havoc\.git/ nocase ascii wide
                        $string52_havoc_offensive_tool_keyword = /Havoc\.hpp/ nocase ascii wide
                        $string53_havoc_offensive_tool_keyword = /havoc\.service/ nocase ascii wide
                        $string54_havoc_offensive_tool_keyword = /havoc\.yaotl/ nocase ascii wide
                        $string55_havoc_offensive_tool_keyword = "Havoc/Client" nocase ascii wide
                        $string56_havoc_offensive_tool_keyword = "Havoc/cmd/" nocase ascii wide
                        $string57_havoc_offensive_tool_keyword = "Havoc/payloads" nocase ascii wide
                        $string58_havoc_offensive_tool_keyword = "Havoc/pkg" nocase ascii wide
                        $string59_havoc_offensive_tool_keyword = "Havoc/Teamserver" nocase ascii wide
                        $string60_havoc_offensive_tool_keyword = /havoc_agent\.py/ nocase ascii wide
                        $string61_havoc_offensive_tool_keyword = /havoc_agent_talon\./ nocase ascii wide
                        $string62_havoc_offensive_tool_keyword = /havoc_default\.yaotl/ nocase ascii wide
                        $string63_havoc_offensive_tool_keyword = "havoc_externalc2" nocase ascii wide
                        $string64_havoc_offensive_tool_keyword = "havoc_service_connect" nocase ascii wide
                        $string65_havoc_offensive_tool_keyword = "havoc-c2-client" nocase ascii wide
                        $string66_havoc_offensive_tool_keyword = "havoc-c2-data" nocase ascii wide
                        $string67_havoc_offensive_tool_keyword = /havocframework\.com/ nocase ascii wide
                        $string68_havoc_offensive_tool_keyword = "HavocService" nocase ascii wide
                        $string69_havoc_offensive_tool_keyword = "HavocTalonInteract" nocase ascii wide
                        $string70_havoc_offensive_tool_keyword = /HavocUi\.cpp/ nocase ascii wide
                        $string71_havoc_offensive_tool_keyword = /HavocUi\.h/ nocase ascii wide
                        $string72_havoc_offensive_tool_keyword = /HavocUI\.hpp/ nocase ascii wide
                        $string73_havoc_offensive_tool_keyword = /http.{0,100}\/demon\.dll/ nocase ascii wide
                        $string74_havoc_offensive_tool_keyword = /http.{0,100}\/demon\.exe/ nocase ascii wide
                        $string75_havoc_offensive_tool_keyword = /implant\.sleep\-obf/ nocase ascii wide
                        $string76_havoc_offensive_tool_keyword = /Implant\\SleepMask/ nocase ascii wide
                        $string77_havoc_offensive_tool_keyword = "inject 1337 /" nocase ascii wide
                        $string78_havoc_offensive_tool_keyword = /inject\.spawn/ nocase ascii wide
                        $string79_havoc_offensive_tool_keyword = /inject\.spoofaddr/ nocase ascii wide
                        $string80_havoc_offensive_tool_keyword = /Injection\\Spawn32/ nocase ascii wide
                        $string81_havoc_offensive_tool_keyword = /Injection\\Spawn64/ nocase ascii wide
                        $string82_havoc_offensive_tool_keyword = /InvokeAssembly\.x64\.dll/ nocase ascii wide
                        $string83_havoc_offensive_tool_keyword = "jump-exec psexec " nocase ascii wide
                        $string84_havoc_offensive_tool_keyword = /nanodump_ppl\.x64\.dll/ nocase ascii wide
                        $string85_havoc_offensive_tool_keyword = /nanodump_ssp\.x64\.dll/ nocase ascii wide
                        $string86_havoc_offensive_tool_keyword = /nanorobeus\.py/ nocase ascii wide
                        $string87_havoc_offensive_tool_keyword = /powerpick\.py/ nocase ascii wide
                        $string88_havoc_offensive_tool_keyword = /PowerPick\.x64\.dll/ nocase ascii wide
                        $string89_havoc_offensive_tool_keyword = /PowershellRunner\.h/ nocase ascii wide
                        $string90_havoc_offensive_tool_keyword = /profiles\/havoc\.yaotl/ nocase ascii wide
                        $string91_havoc_offensive_tool_keyword = /ServiceHavoc\.exe/ nocase ascii wide
                        $string92_havoc_offensive_tool_keyword = "set havoc " nocase ascii wide
                        $string93_havoc_offensive_tool_keyword = "shellcode inject " nocase ascii wide
                        $string94_havoc_offensive_tool_keyword = "shellcode spawn " nocase ascii wide
                        $string95_havoc_offensive_tool_keyword = /Shellcode\.x64\.bin/ nocase ascii wide
                        $string96_havoc_offensive_tool_keyword = "token find-tokens" nocase ascii wide
                        $string97_havoc_offensive_tool_keyword = "token impersonate " nocase ascii wide
                        $string98_havoc_offensive_tool_keyword = "token privs-get" nocase ascii wide
                        $string99_havoc_offensive_tool_keyword = "token privs-list" nocase ascii wide
                        $string100_havoc_offensive_tool_keyword = "token steal " nocase ascii wide
                        $string101_havoc_offensive_tool_keyword = "x-ishavocframework" nocase ascii wide
                        $string102_havoc_offensive_tool_keyword = "dcenum " nocase ascii wide
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