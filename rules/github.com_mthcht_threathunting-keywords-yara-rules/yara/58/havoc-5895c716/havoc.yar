rule havoc
{
    meta:
        description = "Detection patterns for the tool 'havoc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "havoc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdemon\.x64\.exe/ nocase ascii wide
                        $string2 = " havoc-client" nocase ascii wide
                        $string3 = /\.\/donut\s.{0,100}\.exe/
                        $string4 = /\.\/Havoc/
                        $string5 = /\.\/havoc\s/
                        $string6 = "/Cracked5pider/" nocase ascii wide
                        $string7 = /\/demon\.x64\.bin/ nocase ascii wide
                        $string8 = /\/demon\.x64\.exe/ nocase ascii wide
                        $string9 = /\/demon1\.dll/ nocase ascii wide
                        $string10 = /\/demosyscalls\.exe/ nocase ascii wide
                        $string11 = /\/Dialogs\/Payload\.hpp/ nocase ascii wide
                        $string12 = /\/Havoc\.cpp/ nocase ascii wide
                        $string13 = /\/Havoc\.qss/ nocase ascii wide
                        $string14 = /\/Havoc\.rc/ nocase ascii wide
                        $string15 = "/Havoc/data/" nocase ascii wide
                        $string16 = "/Havoc/main/" nocase ascii wide
                        $string17 = "/HavocFramework/" nocase ascii wide
                        $string18 = "/HavocImages/" nocase ascii wide
                        $string19 = "/havoc-py/" nocase ascii wide
                        $string20 = /\/implants\/.{0,100}\/Syscalls\./ nocase ascii wide
                        $string21 = "/Jump-exec/Psexec" nocase ascii wide
                        $string22 = /\/kerberoast\.c/ nocase ascii wide
                        $string23 = /\/kerberoast\.h/ nocase ascii wide
                        $string24 = /\/nanodump\./ nocase ascii wide
                        $string25 = "/payloads/DllLdr/" nocase ascii wide
                        $string26 = /\/RemoteOps\.py/ nocase ascii wide
                        $string27 = /\/scshell\.py/ nocase ascii wide
                        $string28 = /\/Talon\.py/
                        $string29 = /\/Talon\/.{0,100}Agent\/Source/ nocase ascii wide
                        $string30 = /\/Widgets\/LootWidget\./ nocase ascii wide
                        $string31 = /\/WMI\/wmi\.py/ nocase ascii wide
                        $string32 = /\\demon\.dll/ nocase ascii wide
                        $string33 = /\\demon\.x64\.bin/ nocase ascii wide
                        $string34 = /\\demon\.x64\.exe/ nocase ascii wide
                        $string35 = /\\demon1\.dll/ nocase ascii wide
                        $string36 = /\\demosyscalls\.exe/ nocase ascii wide
                        $string37 = /\\Ekko\.exe/ nocase ascii wide
                        $string38 = "40056/service-endpoint" nocase ascii wide
                        $string39 = "5spider:password1234" nocase ascii wide
                        $string40 = /bin\/addusertogroup\.x64/ nocase ascii wide
                        $string41 = /bin\/setuserpass\.x64/ nocase ascii wide
                        $string42 = /Delegation\/delegation\.py/ nocase ascii wide
                        $string43 = /DllLdr\.x64\.bin/ nocase ascii wide
                        $string44 = /Domaininfo\/Domaininfo\.py/ nocase ascii wide
                        $string45 = "dotnet inline-execute " nocase ascii wide
                        $string46 = /externalc2\.py/ nocase ascii wide
                        $string47 = "f5a45c4aa478a7ba9b44654a929bddc2f6453cd8d6f37cd893dda47220ad9870" nocase ascii wide
                        $string48 = "havoc client" nocase ascii wide
                        $string49 = "havoc server" nocase ascii wide
                        $string50 = /havoc\.agent/ nocase ascii wide
                        $string51 = /Havoc\.git/ nocase ascii wide
                        $string52 = /Havoc\.hpp/ nocase ascii wide
                        $string53 = /havoc\.service/ nocase ascii wide
                        $string54 = /havoc\.yaotl/ nocase ascii wide
                        $string55 = "Havoc/Client" nocase ascii wide
                        $string56 = "Havoc/cmd/" nocase ascii wide
                        $string57 = "Havoc/payloads" nocase ascii wide
                        $string58 = "Havoc/pkg" nocase ascii wide
                        $string59 = "Havoc/Teamserver" nocase ascii wide
                        $string60 = /havoc_agent\.py/ nocase ascii wide
                        $string61 = /havoc_agent_talon\./ nocase ascii wide
                        $string62 = /havoc_default\.yaotl/ nocase ascii wide
                        $string63 = "havoc_externalc2" nocase ascii wide
                        $string64 = "havoc_service_connect" nocase ascii wide
                        $string65 = "havoc-c2-client" nocase ascii wide
                        $string66 = "havoc-c2-data" nocase ascii wide
                        $string67 = /havocframework\.com/ nocase ascii wide
                        $string68 = "HavocService" nocase ascii wide
                        $string69 = "HavocTalonInteract" nocase ascii wide
                        $string70 = /HavocUi\.cpp/ nocase ascii wide
                        $string71 = /HavocUi\.h/ nocase ascii wide
                        $string72 = /HavocUI\.hpp/ nocase ascii wide
                        $string73 = /http.{0,100}\/demon\.dll/ nocase ascii wide
                        $string74 = /http.{0,100}\/demon\.exe/ nocase ascii wide
                        $string75 = /implant\.sleep\-obf/ nocase ascii wide
                        $string76 = /Implant\\SleepMask/ nocase ascii wide
                        $string77 = "inject 1337 /" nocase ascii wide
                        $string78 = /inject\.spawn/ nocase ascii wide
                        $string79 = /inject\.spoofaddr/ nocase ascii wide
                        $string80 = /Injection\\Spawn32/ nocase ascii wide
                        $string81 = /Injection\\Spawn64/ nocase ascii wide
                        $string82 = /InvokeAssembly\.x64\.dll/ nocase ascii wide
                        $string83 = "jump-exec psexec " nocase ascii wide
                        $string84 = /nanodump_ppl\.x64\.dll/ nocase ascii wide
                        $string85 = /nanodump_ssp\.x64\.dll/ nocase ascii wide
                        $string86 = /nanorobeus\.py/ nocase ascii wide
                        $string87 = /powerpick\.py/ nocase ascii wide
                        $string88 = /PowerPick\.x64\.dll/ nocase ascii wide
                        $string89 = /PowershellRunner\.h/ nocase ascii wide
                        $string90 = /profiles\/havoc\.yaotl/ nocase ascii wide
                        $string91 = /ServiceHavoc\.exe/ nocase ascii wide
                        $string92 = "set havoc " nocase ascii wide
                        $string93 = "shellcode inject " nocase ascii wide
                        $string94 = "shellcode spawn " nocase ascii wide
                        $string95 = /Shellcode\.x64\.bin/ nocase ascii wide
                        $string96 = "token find-tokens" nocase ascii wide
                        $string97 = "token impersonate " nocase ascii wide
                        $string98 = "token privs-get" nocase ascii wide
                        $string99 = "token privs-list" nocase ascii wide
                        $string100 = "token steal " nocase ascii wide
                        $string101 = "x-ishavocframework" nocase ascii wide
                        $string102 = "dcenum " nocase ascii wide
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