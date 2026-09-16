rule rule_DRSAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DRSAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DRSAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DRSAT_offensive_tool_keyword = /\/DGPOEdit\.zip/ nocase ascii wide
                        $string2_DRSAT_offensive_tool_keyword = /\/DRSAT\.exe/ nocase ascii wide
                        $string3_DRSAT_offensive_tool_keyword = /\/DRSAT\.git/ nocase ascii wide
                        $string4_DRSAT_offensive_tool_keyword = /\/DRSAT\-0\.2\.zip/ nocase ascii wide
                        $string5_DRSAT_offensive_tool_keyword = /\\DGPOEdit\.zip/ nocase ascii wide
                        $string6_DRSAT_offensive_tool_keyword = /\\DRSAT\.exe/ nocase ascii wide
                        $string7_DRSAT_offensive_tool_keyword = /\\DRSAT\-0\.2\.zip/ nocase ascii wide
                        $string8_DRSAT_offensive_tool_keyword = "25522ee1d92c2a6fb9d9dfa01c00ed08b9430cc573c9c4e4a829a1f0cb1670d7" nocase ascii wide
                        $string9_DRSAT_offensive_tool_keyword = "28272a895f6980919f0a7acd8bfda4435c2a1a0b151c90f1113eda1eff12abd0" nocase ascii wide
                        $string10_DRSAT_offensive_tool_keyword = "3a3b32c797443aeda45930d5b13f01d3a263ba4df42b2ed91da4a0e06e9590f7" nocase ascii wide
                        $string11_DRSAT_offensive_tool_keyword = "59a95d191e08984a19d6fca6b65078e372c327624605b68e9c527205eaf455e5" nocase ascii wide
                        $string12_DRSAT_offensive_tool_keyword = "74f34d98822c40027fa388f51791cec58f2bf71c47936616eca08489a4493f61" nocase ascii wide
                        $string13_DRSAT_offensive_tool_keyword = "8af8c2cf6d5bb1a72a9d0ac3a534ba4d68ae6188aea4fbcf93c9fa5ebde47588" nocase ascii wide
                        $string14_DRSAT_offensive_tool_keyword = "8FC203AA-8A90-4A15-B823-E2C3BC4DF0D6" nocase ascii wide
                        $string15_DRSAT_offensive_tool_keyword = "c690e348e6aeb7b59b07a9872ea075ae73102081eeede8816a51534f77dbb62f" nocase ascii wide
                        $string16_DRSAT_offensive_tool_keyword = "CCob/DRSAT" nocase ascii wide
                        $string17_DRSAT_offensive_tool_keyword = "DB62BB65-0E29-4E95-BD4E-0AA543EF74B5" nocase ascii wide
                        $string18_DRSAT_offensive_tool_keyword = "df6b380384faa29656ef09665f3ce25b350fb22712230f0abd8a79739218db15" nocase ascii wide
                        $string19_DRSAT_offensive_tool_keyword = "DRSAT has injected hooks into process " nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}