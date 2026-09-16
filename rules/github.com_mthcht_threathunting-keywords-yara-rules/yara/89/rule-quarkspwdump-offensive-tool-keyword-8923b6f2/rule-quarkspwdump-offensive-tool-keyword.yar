rule rule_quarkspwdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'quarkspwdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "quarkspwdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_quarkspwdump_offensive_tool_keyword = " --dump-bitlocker " nocase ascii wide
                        $string2_quarkspwdump_offensive_tool_keyword = " --dump-bitlocker" nocase ascii wide
                        $string3_quarkspwdump_offensive_tool_keyword = " --dump-hash-domain --with-history" nocase ascii wide
                        $string4_quarkspwdump_offensive_tool_keyword = " --dump-hash-domain" nocase ascii wide
                        $string5_quarkspwdump_offensive_tool_keyword = " --dump-hash-domain-cached" nocase ascii wide
                        $string6_quarkspwdump_offensive_tool_keyword = " --dump-hash-domain-cached" nocase ascii wide
                        $string7_quarkspwdump_offensive_tool_keyword = " --dump-hash-local" nocase ascii wide
                        $string8_quarkspwdump_offensive_tool_keyword = " --ntds-file " nocase ascii wide
                        $string9_quarkspwdump_offensive_tool_keyword = /\/quarkspwdump\.git/ nocase ascii wide
                        $string10_quarkspwdump_offensive_tool_keyword = /\/quarkspwdump\.git/ nocase ascii wide
                        $string11_quarkspwdump_offensive_tool_keyword = /\[\+\]\sLSAKEY\(s\)\sretrieving/ nocase ascii wide
                        $string12_quarkspwdump_offensive_tool_keyword = /\[\+\]\sParsing\sSAM\sregistry\shive/ nocase ascii wide
                        $string13_quarkspwdump_offensive_tool_keyword = /\[\+\]\sParsing\sSAM\sregistry\shive/ nocase ascii wide
                        $string14_quarkspwdump_offensive_tool_keyword = /\[\+\]\sParsing\sSECURITY\sregistry\shive/ nocase ascii wide
                        $string15_quarkspwdump_offensive_tool_keyword = /\[\+\]\sParsing\sSECURITY\sregistry\shive/ nocase ascii wide
                        $string16_quarkspwdump_offensive_tool_keyword = /\[\+\]\sSYSKEY\srestrieving/ nocase ascii wide
                        $string17_quarkspwdump_offensive_tool_keyword = /\[\+\]\sSYSKEY\srestrieving/ nocase ascii wide
                        $string18_quarkspwdump_offensive_tool_keyword = /\\QuarksADDumper\./ nocase ascii wide
                        $string19_quarkspwdump_offensive_tool_keyword = /\\QuarksPwDump/ nocase ascii wide
                        $string20_quarkspwdump_offensive_tool_keyword = /\\QUARKS\-SAM/ nocase ascii wide
                        $string21_quarkspwdump_offensive_tool_keyword = /\\SAM\-.{0,100}\.dmp/ nocase ascii wide
                        $string22_quarkspwdump_offensive_tool_keyword = /\\SAM\-.{0,100}\.dmp\.LOG/ nocase ascii wide
                        $string23_quarkspwdump_offensive_tool_keyword = "07a00b5f4f4d8fd3328b5454dc101d4e76126d9e2600ca2d6fd677452bf624d7" nocase ascii wide
                        $string24_quarkspwdump_offensive_tool_keyword = "07a00b5f4f4d8fd3328b5454dc101d4e76126d9e2600ca2d6fd677452bf624d7" nocase ascii wide
                        $string25_quarkspwdump_offensive_tool_keyword = /ATT_BITLOCKER_MSFVE_RECOVERY_PASSWORD.{0,100}ATTm591788/ nocase ascii wide
                        $string26_quarkspwdump_offensive_tool_keyword = /azizjon\.m\@gmail\.com/ nocase ascii wide
                        $string27_quarkspwdump_offensive_tool_keyword = "d14884d8a7f74e96a4450e1b1e65636b3a2810274963e4a6eb28e161effe1216" nocase ascii wide
                        $string28_quarkspwdump_offensive_tool_keyword = "d14884d8a7f74e96a4450e1b1e65636b3a2810274963e4a6eb28e161effe1216" nocase ascii wide
                        $string29_quarkspwdump_offensive_tool_keyword = /\-\-dump\-bitlocker.{0,100}\-\-ntds\-file\s/ nocase ascii wide
                        $string30_quarkspwdump_offensive_tool_keyword = "E0362605-CC11-4CD5-AFF7-B50934438658" nocase ascii wide
                        $string31_quarkspwdump_offensive_tool_keyword = "E0362605-CC11-4CD5-AFF7-B50934438658" nocase ascii wide
                        $string32_quarkspwdump_offensive_tool_keyword = "No cached domain password found!" nocase ascii wide
                        $string33_quarkspwdump_offensive_tool_keyword = "peterdocter/quarkspwdump" nocase ascii wide
                        $string34_quarkspwdump_offensive_tool_keyword = "QuarksADDumper" nocase ascii wide
                        $string35_quarkspwdump_offensive_tool_keyword = "quarkslab/quarkspwdump" nocase ascii wide
                        $string36_quarkspwdump_offensive_tool_keyword = /quarks\-pwdump\.exe/ nocase ascii wide
                        $string37_quarkspwdump_offensive_tool_keyword = /quarks\-pwdump\.exe/ nocase ascii wide
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