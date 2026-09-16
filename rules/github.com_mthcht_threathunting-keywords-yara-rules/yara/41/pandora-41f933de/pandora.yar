rule pandora
{
    meta:
        description = "Detection patterns for the tool 'pandora' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pandora"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " needs High Integrity Privileges to dump the relevant process!" nocase ascii wide
                        $string2 = /\\1password\\app\\FindsecondPID1password\.h/ nocase ascii wide
                        $string3 = /\\1password\\app\\getCreds1passwordappEntries1\.h/ nocase ascii wide
                        $string4 = /\\1password\\app\\getCreds1passwordappEntries2\.h/ nocase ascii wide
                        $string5 = /\\1password\\app\\getCreds1passwordappMaster\.h/ nocase ascii wide
                        $string6 = /\\1password\\app\\getProcUAC1password\.h/ nocase ascii wide
                        $string7 = /\\1password\\plugin\\getCreds1passwordplugin\.h/ nocase ascii wide
                        $string8 = /\\1password\\plugin\\getCreds1passwordplugin2\.h/ nocase ascii wide
                        $string9 = /\\avira\\getCredsavira\.h/ nocase ascii wide
                        $string10 = /\\avira\\getCredsavira2\.h/ nocase ascii wide
                        $string11 = /\\bitdefender\\getCredsbitdefender\.h/ nocase ascii wide
                        $string12 = /\\bitdefender\\getCredsbitdefender2\.h/ nocase ascii wide
                        $string13 = /\\bitwarden\\plugin\\getCredsbitwardenPluginChrome\.h/ nocase ascii wide
                        $string14 = /\\bitwarden\\plugin\\getCredsbitwardenPluginChrome2\.h/ nocase ascii wide
                        $string15 = /\\chromium\\getCredschromium\.h/ nocase ascii wide
                        $string16 = /\\dashlane\\getCredsdashlaneEntries\.h/ nocase ascii wide
                        $string17 = /\\dashlane\\getCredsdashlaneMaster\.h/ nocase ascii wide
                        $string18 = /\\firefox\\getCredsfirefox\.h/ nocase ascii wide
                        $string19 = /\\firefox\\getCredsfirefox2\.h/ nocase ascii wide
                        $string20 = /\\ironvest\\getCredsironvest\.h/ nocase ascii wide
                        $string21 = /\\kaspersky\\getCredsKasperskyEntries\.h/ nocase ascii wide
                        $string22 = /\\keeper\\getCredskeeper1\.h/ nocase ascii wide
                        $string23 = /\\keeper\\getCredskeeper2\.h/ nocase ascii wide
                        $string24 = /\\keeper\\getCredskeeper3\.h/ nocase ascii wide
                        $string25 = /\\lastpass\\getCredslastpassEntries\.h/ nocase ascii wide
                        $string26 = /\\lastpass\\getCredslastpassMasterPass\.h/ nocase ascii wide
                        $string27 = /\\lastpass\\getCredslastpassMasterUsername\.h/ nocase ascii wide
                        $string28 = /\\norton\\getCredsnorton\.h/ nocase ascii wide
                        $string29 = /\\norton\\getCredsnorton2\.h/ nocase ascii wide
                        $string30 = /\\pandora\.cpp/ nocase ascii wide
                        $string31 = /\\pandora\.sln/ nocase ascii wide
                        $string32 = /\\passwarden\\app\\getCredspasswarden\.h/ nocase ascii wide
                        $string33 = /\\passwarden\\app\\getCredspasswarden2\.h/ nocase ascii wide
                        $string34 = /\\passwordboss\\app\\getCredspasswordbossapp1\.h/ nocase ascii wide
                        $string35 = /\\passwordboss\\app\\getCredspasswordbossapp2\.h/ nocase ascii wide
                        $string36 = /\\roboform\\app\\getCredsroboformapp\.h/ nocase ascii wide
                        $string37 = /\\roboform\\app\\getCredsroboformapp2\.h/ nocase ascii wide
                        $string38 = /\\roboform\\app\\getCredsroboformapp3\.h/ nocase ascii wide
                        $string39 = /\\roboform\\plugin\\getCredsroboformplugin\.h/ nocase ascii wide
                        $string40 = "82F417BE-49BF-44FF-9BBD-64FECEA181D7" nocase ascii wide
                        $string41 = "c1fb599493390e17676176219c5cdd8f4b4bca43696b6a54ded88c9b28f741ff" nocase ascii wide
                        $string42 = "efchatz/pandora" nocase ascii wide
                        $string43 = /getCreds1passwordappEntries1\.h/ nocase ascii wide
                        $string44 = /getCreds1passwordappEntries2\.h/ nocase ascii wide
                        $string45 = /getCreds1passwordappMaster\.h/ nocase ascii wide
                        $string46 = /getCreds1passwordplugin\.h/ nocase ascii wide
                        $string47 = /getCreds1passwordplugin2\.h/ nocase ascii wide
                        $string48 = /getProcUAC1password\.h/ nocase ascii wide
                        $string49 = /Searching\sfor\smaster\scredentials\s\(2\/2\)/ nocase ascii wide
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