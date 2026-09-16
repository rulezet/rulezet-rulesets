rule rule_spoolsploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'spoolsploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spoolsploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_spoolsploit_offensive_tool_keyword = " -a nightmare" nocase ascii wide
                        $string2_spoolsploit_offensive_tool_keyword = " -a spoolsample" nocase ascii wide
                        $string3_spoolsploit_offensive_tool_keyword = /\sevil\.corp\s/ nocase ascii wide
                        $string4_spoolsploit_offensive_tool_keyword = " spoolsploit " nocase ascii wide
                        $string5_spoolsploit_offensive_tool_keyword = /\/smbserver\/smb_server\.py/ nocase ascii wide
                        $string6_spoolsploit_offensive_tool_keyword = "/ssploit/" nocase ascii wide
                        $string7_spoolsploit_offensive_tool_keyword = "--attack nightmare" nocase ascii wide
                        $string8_spoolsploit_offensive_tool_keyword = "--attack spoolsample" nocase ascii wide
                        $string9_spoolsploit_offensive_tool_keyword = "BeetleChunks/SpoolSploit" nocase ascii wide
                        $string10_spoolsploit_offensive_tool_keyword = /impacket\./ nocase ascii wide
                        $string11_spoolsploit_offensive_tool_keyword = /malicious\.dll/ nocase ascii wide
                        $string12_spoolsploit_offensive_tool_keyword = /PrintNightmare\./ nocase ascii wide
                        $string13_spoolsploit_offensive_tool_keyword = /spool_sploit\.py/ nocase ascii wide
                        $string14_spoolsploit_offensive_tool_keyword = "SpoolSploit/" nocase ascii wide
                        $string15_spoolsploit_offensive_tool_keyword = "spoolsploit:latest" nocase ascii wide
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