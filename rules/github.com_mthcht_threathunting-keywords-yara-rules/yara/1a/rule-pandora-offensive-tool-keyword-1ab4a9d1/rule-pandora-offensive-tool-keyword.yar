rule rule_pandora_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pandora' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pandora"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pandora_offensive_tool_keyword = " needs High Integrity Privileges to dump the relevant process!" nocase ascii wide
                        $string2_pandora_offensive_tool_keyword = /\\1password\\app\\FindsecondPID1password\.h/ nocase ascii wide
                        $string3_pandora_offensive_tool_keyword = /\\1password\\app\\getCreds1passwordappEntries1\.h/ nocase ascii wide
                        $string4_pandora_offensive_tool_keyword = /\\1password\\app\\getCreds1passwordappEntries2\.h/ nocase ascii wide
                        $string5_pandora_offensive_tool_keyword = /\\1password\\app\\getCreds1passwordappMaster\.h/ nocase ascii wide
                        $string6_pandora_offensive_tool_keyword = /\\1password\\app\\getProcUAC1password\.h/ nocase ascii wide
                        $string7_pandora_offensive_tool_keyword = /\\1password\\plugin\\getCreds1passwordplugin\.h/ nocase ascii wide
                        $string8_pandora_offensive_tool_keyword = /\\1password\\plugin\\getCreds1passwordplugin2\.h/ nocase ascii wide
                        $string9_pandora_offensive_tool_keyword = /\\avira\\getCredsavira\.h/ nocase ascii wide
                        $string10_pandora_offensive_tool_keyword = /\\avira\\getCredsavira2\.h/ nocase ascii wide
                        $string11_pandora_offensive_tool_keyword = /\\bitdefender\\getCredsbitdefender\.h/ nocase ascii wide
                        $string12_pandora_offensive_tool_keyword = /\\bitdefender\\getCredsbitdefender2\.h/ nocase ascii wide
                        $string13_pandora_offensive_tool_keyword = /\\bitwarden\\plugin\\getCredsbitwardenPluginChrome\.h/ nocase ascii wide
                        $string14_pandora_offensive_tool_keyword = /\\bitwarden\\plugin\\getCredsbitwardenPluginChrome2\.h/ nocase ascii wide
                        $string15_pandora_offensive_tool_keyword = /\\chromium\\getCredschromium\.h/ nocase ascii wide
                        $string16_pandora_offensive_tool_keyword = /\\dashlane\\getCredsdashlaneEntries\.h/ nocase ascii wide
                        $string17_pandora_offensive_tool_keyword = /\\dashlane\\getCredsdashlaneMaster\.h/ nocase ascii wide
                        $string18_pandora_offensive_tool_keyword = /\\firefox\\getCredsfirefox\.h/ nocase ascii wide
                        $string19_pandora_offensive_tool_keyword = /\\firefox\\getCredsfirefox2\.h/ nocase ascii wide
                        $string20_pandora_offensive_tool_keyword = /\\ironvest\\getCredsironvest\.h/ nocase ascii wide
                        $string21_pandora_offensive_tool_keyword = /\\kaspersky\\getCredsKasperskyEntries\.h/ nocase ascii wide
                        $string22_pandora_offensive_tool_keyword = /\\keeper\\getCredskeeper1\.h/ nocase ascii wide
                        $string23_pandora_offensive_tool_keyword = /\\keeper\\getCredskeeper2\.h/ nocase ascii wide
                        $string24_pandora_offensive_tool_keyword = /\\keeper\\getCredskeeper3\.h/ nocase ascii wide
                        $string25_pandora_offensive_tool_keyword = /\\lastpass\\getCredslastpassEntries\.h/ nocase ascii wide
                        $string26_pandora_offensive_tool_keyword = /\\lastpass\\getCredslastpassMasterPass\.h/ nocase ascii wide
                        $string27_pandora_offensive_tool_keyword = /\\lastpass\\getCredslastpassMasterUsername\.h/ nocase ascii wide
                        $string28_pandora_offensive_tool_keyword = /\\norton\\getCredsnorton\.h/ nocase ascii wide
                        $string29_pandora_offensive_tool_keyword = /\\norton\\getCredsnorton2\.h/ nocase ascii wide
                        $string30_pandora_offensive_tool_keyword = /\\pandora\.cpp/ nocase ascii wide
                        $string31_pandora_offensive_tool_keyword = /\\pandora\.sln/ nocase ascii wide
                        $string32_pandora_offensive_tool_keyword = /\\passwarden\\app\\getCredspasswarden\.h/ nocase ascii wide
                        $string33_pandora_offensive_tool_keyword = /\\passwarden\\app\\getCredspasswarden2\.h/ nocase ascii wide
                        $string34_pandora_offensive_tool_keyword = /\\passwordboss\\app\\getCredspasswordbossapp1\.h/ nocase ascii wide
                        $string35_pandora_offensive_tool_keyword = /\\passwordboss\\app\\getCredspasswordbossapp2\.h/ nocase ascii wide
                        $string36_pandora_offensive_tool_keyword = /\\roboform\\app\\getCredsroboformapp\.h/ nocase ascii wide
                        $string37_pandora_offensive_tool_keyword = /\\roboform\\app\\getCredsroboformapp2\.h/ nocase ascii wide
                        $string38_pandora_offensive_tool_keyword = /\\roboform\\app\\getCredsroboformapp3\.h/ nocase ascii wide
                        $string39_pandora_offensive_tool_keyword = /\\roboform\\plugin\\getCredsroboformplugin\.h/ nocase ascii wide
                        $string40_pandora_offensive_tool_keyword = "82F417BE-49BF-44FF-9BBD-64FECEA181D7" nocase ascii wide
                        $string41_pandora_offensive_tool_keyword = "c1fb599493390e17676176219c5cdd8f4b4bca43696b6a54ded88c9b28f741ff" nocase ascii wide
                        $string42_pandora_offensive_tool_keyword = "efchatz/pandora" nocase ascii wide
                        $string43_pandora_offensive_tool_keyword = /getCreds1passwordappEntries1\.h/ nocase ascii wide
                        $string44_pandora_offensive_tool_keyword = /getCreds1passwordappEntries2\.h/ nocase ascii wide
                        $string45_pandora_offensive_tool_keyword = /getCreds1passwordappMaster\.h/ nocase ascii wide
                        $string46_pandora_offensive_tool_keyword = /getCreds1passwordplugin\.h/ nocase ascii wide
                        $string47_pandora_offensive_tool_keyword = /getCreds1passwordplugin2\.h/ nocase ascii wide
                        $string48_pandora_offensive_tool_keyword = /getProcUAC1password\.h/ nocase ascii wide
                        $string49_pandora_offensive_tool_keyword = /Searching\sfor\smaster\scredentials\s\(2\/2\)/ nocase ascii wide
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