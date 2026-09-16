rule rule_nanorobeus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nanorobeus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nanorobeus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nanorobeus_offensive_tool_keyword = /\skekeo\/modules\/kull_m_memory\.c/ nocase ascii wide
                        $string2_nanorobeus_offensive_tool_keyword = " kerberoast /spn:" nocase ascii wide
                        $string3_nanorobeus_offensive_tool_keyword = " tgtdeleg /spn:cifs" nocase ascii wide
                        $string4_nanorobeus_offensive_tool_keyword = /\/kerberoast\.c/ nocase ascii wide
                        $string5_nanorobeus_offensive_tool_keyword = /\/modules\/kull_m_crypto_system\.h/
                        $string6_nanorobeus_offensive_tool_keyword = /\/nanorobeus\.git/ nocase ascii wide
                        $string7_nanorobeus_offensive_tool_keyword = /\\include\\kerberoast\.h/ nocase ascii wide
                        $string8_nanorobeus_offensive_tool_keyword = /\\kerberoast\.c/ nocase ascii wide
                        $string9_nanorobeus_offensive_tool_keyword = /\\kerberoast\.c/ nocase ascii wide
                        $string10_nanorobeus_offensive_tool_keyword = /\\nanorobeus\-main\.zip/ nocase ascii wide
                        $string11_nanorobeus_offensive_tool_keyword = /\\sample_brc4\.json/ nocase ascii wide
                        $string12_nanorobeus_offensive_tool_keyword = /\\sample_sliver\.json/ nocase ascii wide
                        $string13_nanorobeus_offensive_tool_keyword = /dist.{0,100}_brc4\.x64\.o/ nocase ascii wide
                        $string14_nanorobeus_offensive_tool_keyword = /dist.{0,100}_brc4\.x86\.o/ nocase ascii wide
                        $string15_nanorobeus_offensive_tool_keyword = /dist\/nanorobeus_cs\./ nocase ascii wide
                        $string16_nanorobeus_offensive_tool_keyword = /nanorobeus.{0,100}_cs\.x64\./ nocase ascii wide
                        $string17_nanorobeus_offensive_tool_keyword = /nanorobeus.{0,100}_cs\.x86\./ nocase ascii wide
                        $string18_nanorobeus_offensive_tool_keyword = /nanorobeus.{0,100}dump/ nocase ascii wide
                        $string19_nanorobeus_offensive_tool_keyword = /nanorobeus\.cna/ nocase ascii wide
                        $string20_nanorobeus_offensive_tool_keyword = /nanorobeus\.x64/ nocase ascii wide
                        $string21_nanorobeus_offensive_tool_keyword = /nanorobeus\.x86/ nocase ascii wide
                        $string22_nanorobeus_offensive_tool_keyword = "nanorobeus_brc4" nocase ascii wide
                        $string23_nanorobeus_offensive_tool_keyword = "nanorobeus64" nocase ascii wide
                        $string24_nanorobeus_offensive_tool_keyword = "nanorobeus86" nocase ascii wide
                        $string25_nanorobeus_offensive_tool_keyword = "nanorobeus-main" nocase ascii wide
                        $string26_nanorobeus_offensive_tool_keyword = /sample_brc4\.json/ nocase ascii wide
                        $string27_nanorobeus_offensive_tool_keyword = "wavvs/nanorobeus" nocase ascii wide
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