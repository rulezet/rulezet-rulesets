rule rule_silenttrinity_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'silenttrinity' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "silenttrinity"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_silenttrinity_offensive_tool_keyword = /\ssilenttrinity\./ nocase ascii wide
                        $string2_silenttrinity_offensive_tool_keyword = " st client wss://" nocase ascii wide
                        $string3_silenttrinity_offensive_tool_keyword = " st teamserver " nocase ascii wide
                        $string4_silenttrinity_offensive_tool_keyword = /\.\\stager\.ps1/ nocase ascii wide
                        $string5_silenttrinity_offensive_tool_keyword = /\/shellcode\.bin/ nocase ascii wide
                        $string6_silenttrinity_offensive_tool_keyword = /\/shellcode\.hex/ nocase ascii wide
                        $string7_silenttrinity_offensive_tool_keyword = /\/silenttrinity\/.{0,100}\.py/ nocase ascii wide
                        $string8_silenttrinity_offensive_tool_keyword = /_peloader\.dll/ nocase ascii wide
                        $string9_silenttrinity_offensive_tool_keyword = /alwaysinstallelevated\./ nocase ascii wide
                        $string10_silenttrinity_offensive_tool_keyword = /bypassUAC.{0,100}\.boo/ nocase ascii wide
                        $string11_silenttrinity_offensive_tool_keyword = /bypassUAC.{0,100}\.py/ nocase ascii wide
                        $string12_silenttrinity_offensive_tool_keyword = "core/teamserver/stagers/" nocase ascii wide
                        $string13_silenttrinity_offensive_tool_keyword = /credphisher\.py/ nocase ascii wide
                        $string14_silenttrinity_offensive_tool_keyword = /dumpVaultCredentials\.py/ nocase ascii wide
                        $string15_silenttrinity_offensive_tool_keyword = /excelshellinject\./ nocase ascii wide
                        $string16_silenttrinity_offensive_tool_keyword = /hijackCLSIDpersistence\./ nocase ascii wide
                        $string17_silenttrinity_offensive_tool_keyword = /impersonateprocess\.py/ nocase ascii wide
                        $string18_silenttrinity_offensive_tool_keyword = /impersonateuser\.boo/ nocase ascii wide
                        $string19_silenttrinity_offensive_tool_keyword = /impersonateuser\.py/ nocase ascii wide
                        $string20_silenttrinity_offensive_tool_keyword = /injectremote\.boo/ nocase ascii wide
                        $string21_silenttrinity_offensive_tool_keyword = /kerberoasting\.boo/ nocase ascii wide
                        $string22_silenttrinity_offensive_tool_keyword = /mouseshaker\./ nocase ascii wide
                        $string23_silenttrinity_offensive_tool_keyword = /netloggedonusers\./ nocase ascii wide
                        $string24_silenttrinity_offensive_tool_keyword = /pathhijack\.py/ nocase ascii wide
                        $string25_silenttrinity_offensive_tool_keyword = /portscanner\.py/ nocase ascii wide
                        $string26_silenttrinity_offensive_tool_keyword = /posh_stageless\.py/ nocase ascii wide
                        $string27_silenttrinity_offensive_tool_keyword = "python 3 st teamserver " nocase ascii wide
                        $string28_silenttrinity_offensive_tool_keyword = /python\sst\.py/ nocase ascii wide
                        $string29_silenttrinity_offensive_tool_keyword = "python3 st client wss://" nocase ascii wide
                        $string30_silenttrinity_offensive_tool_keyword = /python3\sst\.py/ nocase ascii wide
                        $string31_silenttrinity_offensive_tool_keyword = "SILENTTRINITY" nocase ascii wide
                        $string32_silenttrinity_offensive_tool_keyword = /silenttrinity.{0,100}\.dll/ nocase ascii wide
                        $string33_silenttrinity_offensive_tool_keyword = /specialtokengroupprivs\.py/ nocase ascii wide
                        $string34_silenttrinity_offensive_tool_keyword = /startupfolderperistence\.py/ nocase ascii wide
                        $string35_silenttrinity_offensive_tool_keyword = "use powershell_stageless" nocase ascii wide
                        $string36_silenttrinity_offensive_tool_keyword = "use safetykatz" nocase ascii wide
                        $string37_silenttrinity_offensive_tool_keyword = /vnperistence\.py/ nocase ascii wide
                        $string38_silenttrinity_offensive_tool_keyword = /WMIExecHash\./ nocase ascii wide
                        $string39_silenttrinity_offensive_tool_keyword = /WMIExecHash\.boo/ nocase ascii wide
                        $string40_silenttrinity_offensive_tool_keyword = /wmipersistence\.py/ nocase ascii wide
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