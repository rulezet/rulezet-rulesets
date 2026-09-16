rule rule_Inveigh_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Inveigh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Inveigh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Inveigh_offensive_tool_keyword = /\sInveigh\.ps1/ nocase ascii wide
                        $string2_Inveigh_offensive_tool_keyword = /\s\-IP\s.{0,100}\s\-SpooferIP\s.{0,100}\s\-HTTP\sN/ nocase ascii wide
                        $string3_Inveigh_offensive_tool_keyword = " -llmnrtypes AAAA" nocase ascii wide
                        $string4_Inveigh_offensive_tool_keyword = " -mdns y -mdnsunicast n" nocase ascii wide
                        $string5_Inveigh_offensive_tool_keyword = " -NBNSBruteForce" nocase ascii wide
                        $string6_Inveigh_offensive_tool_keyword = " -p:AssemblyName=inveigh" nocase ascii wide
                        $string7_Inveigh_offensive_tool_keyword = /\.exe\s\-sniffer\sn/ nocase ascii wide
                        $string8_Inveigh_offensive_tool_keyword = /\/Inveigh\.git/ nocase ascii wide
                        $string9_Inveigh_offensive_tool_keyword = /\/Inveigh\.ps1/ nocase ascii wide
                        $string10_Inveigh_offensive_tool_keyword = /\/Inveigh\-Cleartext\.txt/
                        $string11_Inveigh_offensive_tool_keyword = /\/Inveigh\-FormInput\.txt/
                        $string12_Inveigh_offensive_tool_keyword = /\/Inveigh\-Log\.txt/
                        $string13_Inveigh_offensive_tool_keyword = /\/Inveigh\-NTLMv1\.txt/
                        $string14_Inveigh_offensive_tool_keyword = /\/Inveigh\-NTLMv2\.txt/
                        $string15_Inveigh_offensive_tool_keyword = /\\Inveigh\.exe/ nocase ascii wide
                        $string16_Inveigh_offensive_tool_keyword = /\\inveigh\.log/ nocase ascii wide
                        $string17_Inveigh_offensive_tool_keyword = /\\Inveigh\.ps1/ nocase ascii wide
                        $string18_Inveigh_offensive_tool_keyword = /\\Inveigh\.psd1/ nocase ascii wide
                        $string19_Inveigh_offensive_tool_keyword = /\\Inveigh\\bin\\/ nocase ascii wide
                        $string20_Inveigh_offensive_tool_keyword = /\\Inveigh\-Cleartext\.txt/ nocase ascii wide
                        $string21_Inveigh_offensive_tool_keyword = /\\Inveigh\-FormInput\.txt/ nocase ascii wide
                        $string22_Inveigh_offensive_tool_keyword = /\\Inveigh\-Log\.txt/ nocase ascii wide
                        $string23_Inveigh_offensive_tool_keyword = /\\Inveigh\-NTLMv1\.txt/ nocase ascii wide
                        $string24_Inveigh_offensive_tool_keyword = /\\Inveigh\-NTLMv2\.txt/ nocase ascii wide
                        $string25_Inveigh_offensive_tool_keyword = /dotnet\sInveigh\.dll/ nocase ascii wide
                        $string26_Inveigh_offensive_tool_keyword = /Inveigh\.ps1/ nocase ascii wide
                        $string27_Inveigh_offensive_tool_keyword = /Inveigh\.psd1/ nocase ascii wide
                        $string28_Inveigh_offensive_tool_keyword = /Inveigh\.psm1/ nocase ascii wide
                        $string29_Inveigh_offensive_tool_keyword = /Inveigh\.sln/ nocase ascii wide
                        $string30_Inveigh_offensive_tool_keyword = /Inveigh\-Cleartext\.txt/ nocase ascii wide
                        $string31_Inveigh_offensive_tool_keyword = /Inveigh\-FormInput\.txt/ nocase ascii wide
                        $string32_Inveigh_offensive_tool_keyword = /Inveigh\-Log\.txt/ nocase ascii wide
                        $string33_Inveigh_offensive_tool_keyword = "Inveigh-master" nocase ascii wide
                        $string34_Inveigh_offensive_tool_keyword = /Inveigh\-net.{0,100}\.zip/ nocase ascii wide
                        $string35_Inveigh_offensive_tool_keyword = /Inveigh\-NTLMv1\.txt/ nocase ascii wide
                        $string36_Inveigh_offensive_tool_keyword = /Inveigh\-NTLMv2\.txt/ nocase ascii wide
                        $string37_Inveigh_offensive_tool_keyword = /Inveigh\-Relay\.ps1/ nocase ascii wide
                        $string38_Inveigh_offensive_tool_keyword = /inveighzero\.exe/ nocase ascii wide
                        $string39_Inveigh_offensive_tool_keyword = "Invoke-Inveigh" nocase ascii wide
                        $string40_Inveigh_offensive_tool_keyword = "Kevin-Robertson/Inveigh" nocase ascii wide
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