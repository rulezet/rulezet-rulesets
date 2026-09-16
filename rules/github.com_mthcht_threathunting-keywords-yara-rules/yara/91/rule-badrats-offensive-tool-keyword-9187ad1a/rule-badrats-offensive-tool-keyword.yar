rule rule_badrats_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'badrats' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "badrats"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_badrats_offensive_tool_keyword = /\sbadrat\.ps1/ nocase ascii wide
                        $string2_badrats_offensive_tool_keyword = /\sbadrat_cs\.exe/ nocase ascii wide
                        $string3_badrats_offensive_tool_keyword = /\sbadrat_server\.py/ nocase ascii wide
                        $string4_badrats_offensive_tool_keyword = /\s\-o\:badrat\.xll\s/ nocase ascii wide
                        $string5_badrats_offensive_tool_keyword = /\/badrat\.ps1/ nocase ascii wide
                        $string6_badrats_offensive_tool_keyword = /\/badrat_cs\.exe/ nocase ascii wide
                        $string7_badrats_offensive_tool_keyword = /\/badrat_server\.py/ nocase ascii wide
                        $string8_badrats_offensive_tool_keyword = /\/badrats\.git/ nocase ascii wide
                        $string9_badrats_offensive_tool_keyword = /\/dbsclrxcvg\/b\.js/ nocase ascii wide
                        $string10_badrats_offensive_tool_keyword = "/rats/badrat_cs/" nocase ascii wide
                        $string11_badrats_offensive_tool_keyword = /\[\!\]\sFeature\sis\sunsupported\sfor\sPS1\srats/ nocase ascii wide
                        $string12_badrats_offensive_tool_keyword = /\[\!\]\sNim\sand\sC\#\sare\sthe\sonly\slanguage\scapable\sof\sexecuting\sBOFS/ nocase ascii wide
                        $string13_badrats_offensive_tool_keyword = /\\badrat\.ps1/ nocase ascii wide
                        $string14_badrats_offensive_tool_keyword = /\\badrat_cs\.exe/ nocase ascii wide
                        $string15_badrats_offensive_tool_keyword = /\\badrat_server\.py/ nocase ascii wide
                        $string16_badrats_offensive_tool_keyword = /\\rats\\badrat_cs\\/ nocase ascii wide
                        $string17_badrats_offensive_tool_keyword = /\\rats\\js_downloader\.vba/ nocase ascii wide
                        $string18_badrats_offensive_tool_keyword = /\\shellcode_createproc\.xml/ nocase ascii wide
                        $string19_badrats_offensive_tool_keyword = /\]\sCleared\sall\srat\scommand\squeues\!/ nocase ascii wide
                        $string20_badrats_offensive_tool_keyword = "79520C3A-4931-46EB-92D7-334DA7FC9013" nocase ascii wide
                        $string21_badrats_offensive_tool_keyword = /badrat\.smb\.hta/ nocase ascii wide
                        $string22_badrats_offensive_tool_keyword = /badrat\.smb\.js/ nocase ascii wide
                        $string23_badrats_offensive_tool_keyword = /badrat_cs\.csproj/ nocase ascii wide
                        $string24_badrats_offensive_tool_keyword = /badrat_cs\.exe\s/ nocase ascii wide
                        $string25_badrats_offensive_tool_keyword = /badrat_cs\.exe\.config/ nocase ascii wide
                        $string26_badrats_offensive_tool_keyword = /badrat_server\.py\s/ nocase ascii wide
                        $string27_badrats_offensive_tool_keyword = /badrats\-c2\-initial\-access\-payloads\.html/ nocase ascii wide
                        $string28_badrats_offensive_tool_keyword = /badrats\-master\.zip/ nocase ascii wide
                        $string29_badrats_offensive_tool_keyword = /Invoke\-Bloodhound\.ps1/ nocase ascii wide
                        $string30_badrats_offensive_tool_keyword = "Invoke-ReverseSocksProxy" nocase ascii wide
                        $string31_badrats_offensive_tool_keyword = /Invoke\-SocksProxy\.ps1/ nocase ascii wide
                        $string32_badrats_offensive_tool_keyword = "KevinJClark/badrats" nocase ascii wide
                        $string33_badrats_offensive_tool_keyword = /rat\scommunications\sare\sNOT\sSECURE\.\sDo\snot\ssend\ssensitive\sinfo\sthrough\sthe\sC2\schannel\sunless\susing\sSSL/ nocase ascii wide
                        $string34_badrats_offensive_tool_keyword = /send_invoke_shellcode\(.{0,100}ratID/ nocase ascii wide
                        $string35_badrats_offensive_tool_keyword = /send_ratcode\(ratID\=/ nocase ascii wide
                        $string36_badrats_offensive_tool_keyword = /send_shellcode_msbuild_xml\(.{0,100}ratID/ nocase ascii wide
                        $string37_badrats_offensive_tool_keyword = /sends\sthe\sjscript\sfile\sto\sthe\srat\s\(JS\sand\sHTA\sonly\)\sto\sbe\sevaulated\sin\sline\.\sUseful\sfor\sGadget2JS\spayloads/ nocase ascii wide
                        $string38_badrats_offensive_tool_keyword = "set-shellcode-process default" nocase ascii wide
                        $string39_badrats_offensive_tool_keyword = /SharpDump\.exe/ nocase ascii wide
                        $string40_badrats_offensive_tool_keyword = /shellcode_injectproc\.xml/ nocase ascii wide
                        $string41_badrats_offensive_tool_keyword = "unlink -- tells the current rat to disconnect from a child rat given a local file or UNC path" nocase ascii wide
                        $string42_badrats_offensive_tool_keyword = /xor_crypt_and_encode\(/ nocase ascii wide
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