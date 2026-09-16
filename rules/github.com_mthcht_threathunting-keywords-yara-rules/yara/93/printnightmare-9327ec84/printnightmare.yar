rule PrintNightmare
{
    meta:
        description = "Detection patterns for the tool 'PrintNightmare' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrintNightmare"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " = \"NeverGonnaRunAroundAndDesertYou\"" nocase ascii wide
                        $string2 = " Invoke-Nightmare" nocase ascii wide
                        $string3 = " namespace SharpPrintNightmare" nocase ascii wide
                        $string4 = /\$DriverName\s\=\s\\"Totally\sNot\sMalicious\\"/ nocase ascii wide
                        $string5 = /\/CVE\-2021\-1675\.git/ nocase ascii wide
                        $string6 = /\/PrintNightmare\.git/ nocase ascii wide
                        $string7 = /\[\+\]\sExploit\sCompleted/ nocase ascii wide
                        $string8 = /\\PrintNightmare\./ nocase ascii wide
                        $string9 = "0CD16C7B-2A65-44E5-AB74-843BD23241D3" nocase ascii wide
                        $string10 = "0eec76148fd7a3b1eb54d3fa71c30b5370d410e1eb81231ff0e9e66de3598aea" nocase ascii wide
                        $string11 = "290083a0a3dac6b3c05ab3e01fb5cdfb128c0175914f1fe64cdb1a5e247d43f0" nocase ascii wide
                        $string12 = "2daeb177f86c873780c59e59fa8c424e45aea199bf5fb3e935310b043d41787f" nocase ascii wide
                        $string13 = "4709b94c38800c9a400aeee54241b107b8fd597f34e3283949a18537f2ae04a7" nocase ascii wide
                        $string14 = "55b8235e7a749bac3ce56589298727a4314ea2e2ac9ba706b183ca3781cc16f8" nocase ascii wide
                        $string15 = "5FEB114B-49EC-4652-B29E-8CB5E752EC3E" nocase ascii wide
                        $string16 = "5FEB114B-49EC-4652-B29E-8CB5E752EC3E" nocase ascii wide
                        $string17 = "b8f5ed1345cb6970bd21babe5a58d45e035a9ecd04b961b995b2a03023beea87" nocase ascii wide
                        $string18 = "BBFBAF1D-A01E-4615-A208-786147320C20" nocase ascii wide
                        $string19 = "calebstewart/CVE-2021-1675" nocase ascii wide
                        $string20 = "cube0x0/CVE-2021-1675" nocase ascii wide
                        $string21 = /CVE\-2021\-1675\.ps1/ nocase ascii wide
                        $string22 = /CVE\-2021\-1675\.py/ nocase ascii wide
                        $string23 = "D30C9D6B-1F45-47BD-825B-389FE8CC9069" nocase ascii wide
                        $string24 = "Invoke-Nightmare " nocase ascii wide
                        $string25 = "misc::printnightmare" nocase ascii wide
                        $string26 = "outflanknl/PrintNightmare" nocase ascii wide
                        $string27 = /PrintNightmare\.dll/ nocase ascii wide
                        $string28 = /SharpPrintNightmare\.exe/ nocase ascii wide
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