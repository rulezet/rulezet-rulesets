rule silenttrinity
{
    meta:
        description = "Detection patterns for the tool 'silenttrinity' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "silenttrinity"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\ssilenttrinity\./ nocase ascii wide
                        $string2 = " st client wss://" nocase ascii wide
                        $string3 = " st teamserver " nocase ascii wide
                        $string4 = /\.\\stager\.ps1/ nocase ascii wide
                        $string5 = /\/shellcode\.bin/ nocase ascii wide
                        $string6 = /\/shellcode\.hex/ nocase ascii wide
                        $string7 = /\/silenttrinity\/.{0,100}\.py/ nocase ascii wide
                        $string8 = /_peloader\.dll/ nocase ascii wide
                        $string9 = /alwaysinstallelevated\./ nocase ascii wide
                        $string10 = /bypassUAC.{0,100}\.boo/ nocase ascii wide
                        $string11 = /bypassUAC.{0,100}\.py/ nocase ascii wide
                        $string12 = "core/teamserver/stagers/" nocase ascii wide
                        $string13 = /credphisher\.py/ nocase ascii wide
                        $string14 = /dumpVaultCredentials\.py/ nocase ascii wide
                        $string15 = /excelshellinject\./ nocase ascii wide
                        $string16 = /hijackCLSIDpersistence\./ nocase ascii wide
                        $string17 = /impersonateprocess\.py/ nocase ascii wide
                        $string18 = /impersonateuser\.boo/ nocase ascii wide
                        $string19 = /impersonateuser\.py/ nocase ascii wide
                        $string20 = /injectremote\.boo/ nocase ascii wide
                        $string21 = /kerberoasting\.boo/ nocase ascii wide
                        $string22 = /mouseshaker\./ nocase ascii wide
                        $string23 = /netloggedonusers\./ nocase ascii wide
                        $string24 = /pathhijack\.py/ nocase ascii wide
                        $string25 = /portscanner\.py/ nocase ascii wide
                        $string26 = /posh_stageless\.py/ nocase ascii wide
                        $string27 = "python 3 st teamserver " nocase ascii wide
                        $string28 = /python\sst\.py/ nocase ascii wide
                        $string29 = "python3 st client wss://" nocase ascii wide
                        $string30 = /python3\sst\.py/ nocase ascii wide
                        $string31 = "SILENTTRINITY" nocase ascii wide
                        $string32 = /silenttrinity.{0,100}\.dll/ nocase ascii wide
                        $string33 = /specialtokengroupprivs\.py/ nocase ascii wide
                        $string34 = /startupfolderperistence\.py/ nocase ascii wide
                        $string35 = "use powershell_stageless" nocase ascii wide
                        $string36 = "use safetykatz" nocase ascii wide
                        $string37 = /vnperistence\.py/ nocase ascii wide
                        $string38 = /WMIExecHash\./ nocase ascii wide
                        $string39 = /WMIExecHash\.boo/ nocase ascii wide
                        $string40 = /wmipersistence\.py/ nocase ascii wide
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