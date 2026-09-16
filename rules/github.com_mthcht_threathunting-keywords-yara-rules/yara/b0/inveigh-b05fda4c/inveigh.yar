rule Inveigh
{
    meta:
        description = "Detection patterns for the tool 'Inveigh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Inveigh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sInveigh\.ps1/ nocase ascii wide
                        $string2 = /\s\-IP\s.{0,100}\s\-SpooferIP\s.{0,100}\s\-HTTP\sN/ nocase ascii wide
                        $string3 = " -llmnrtypes AAAA" nocase ascii wide
                        $string4 = " -mdns y -mdnsunicast n" nocase ascii wide
                        $string5 = " -NBNSBruteForce" nocase ascii wide
                        $string6 = " -p:AssemblyName=inveigh" nocase ascii wide
                        $string7 = /\.exe\s\-sniffer\sn/ nocase ascii wide
                        $string8 = /\/Inveigh\.git/ nocase ascii wide
                        $string9 = /\/Inveigh\.ps1/ nocase ascii wide
                        $string10 = /\/Inveigh\-Cleartext\.txt/
                        $string11 = /\/Inveigh\-FormInput\.txt/
                        $string12 = /\/Inveigh\-Log\.txt/
                        $string13 = /\/Inveigh\-NTLMv1\.txt/
                        $string14 = /\/Inveigh\-NTLMv2\.txt/
                        $string15 = /\\Inveigh\.exe/ nocase ascii wide
                        $string16 = /\\inveigh\.log/ nocase ascii wide
                        $string17 = /\\Inveigh\.ps1/ nocase ascii wide
                        $string18 = /\\Inveigh\.psd1/ nocase ascii wide
                        $string19 = /\\Inveigh\\bin\\/ nocase ascii wide
                        $string20 = /\\Inveigh\-Cleartext\.txt/ nocase ascii wide
                        $string21 = /\\Inveigh\-FormInput\.txt/ nocase ascii wide
                        $string22 = /\\Inveigh\-Log\.txt/ nocase ascii wide
                        $string23 = /\\Inveigh\-NTLMv1\.txt/ nocase ascii wide
                        $string24 = /\\Inveigh\-NTLMv2\.txt/ nocase ascii wide
                        $string25 = /dotnet\sInveigh\.dll/ nocase ascii wide
                        $string26 = /Inveigh\.ps1/ nocase ascii wide
                        $string27 = /Inveigh\.psd1/ nocase ascii wide
                        $string28 = /Inveigh\.psm1/ nocase ascii wide
                        $string29 = /Inveigh\.sln/ nocase ascii wide
                        $string30 = /Inveigh\-Cleartext\.txt/ nocase ascii wide
                        $string31 = /Inveigh\-FormInput\.txt/ nocase ascii wide
                        $string32 = /Inveigh\-Log\.txt/ nocase ascii wide
                        $string33 = "Inveigh-master" nocase ascii wide
                        $string34 = /Inveigh\-net.{0,100}\.zip/ nocase ascii wide
                        $string35 = /Inveigh\-NTLMv1\.txt/ nocase ascii wide
                        $string36 = /Inveigh\-NTLMv2\.txt/ nocase ascii wide
                        $string37 = /Inveigh\-Relay\.ps1/ nocase ascii wide
                        $string38 = /inveighzero\.exe/ nocase ascii wide
                        $string39 = "Invoke-Inveigh" nocase ascii wide
                        $string40 = "Kevin-Robertson/Inveigh" nocase ascii wide
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