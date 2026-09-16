rule rule_AutoBlue_MS17_010_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AutoBlue-MS17-010' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoBlue-MS17-010"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AutoBlue_MS17_010_offensive_tool_keyword = /\/AutoBlue\-MS17\-010\.git/ nocase ascii wide
                        $string2_AutoBlue_MS17_010_offensive_tool_keyword = /\/eternal_checker\.py/ nocase ascii wide
                        $string3_AutoBlue_MS17_010_offensive_tool_keyword = /\/zzz_exploit\.py/ nocase ascii wide
                        $string4_AutoBlue_MS17_010_offensive_tool_keyword = /\\AutoBlue\-MS17\-010\-main/ nocase ascii wide
                        $string5_AutoBlue_MS17_010_offensive_tool_keyword = "0ad2c8d20a383ac7007bb531672f8cbb9fe945b8d32eefa061b4ead09ff92ce3" nocase ascii wide
                        $string6_AutoBlue_MS17_010_offensive_tool_keyword = "1008626761b65900ab77833ff6a2a3e2a4d8a7a4eab1e956d477d951f1edd28e" nocase ascii wide
                        $string7_AutoBlue_MS17_010_offensive_tool_keyword = "2d93db2abb0ea20a402c5d62e610e36d1957069b8612f7fd05d6be0a1d362c3b" nocase ascii wide
                        $string8_AutoBlue_MS17_010_offensive_tool_keyword = "3ndG4me/AutoBlue-MS17-010" nocase ascii wide
                        $string9_AutoBlue_MS17_010_offensive_tool_keyword = "4be7282a5c184870c130913381641c2c531d773eec25fc810394fca9ec9c386c" nocase ascii wide
                        $string10_AutoBlue_MS17_010_offensive_tool_keyword = "5649329377ee03a1aace70be74650290f8d6bb597351daf62d1a6a4a37db53cb" nocase ascii wide
                        $string11_AutoBlue_MS17_010_offensive_tool_keyword = "89d678050ee670535a84b9e38557f626b1c704a9998e528a58e7cee830378283" nocase ascii wide
                        $string12_AutoBlue_MS17_010_offensive_tool_keyword = "b5822ac44575655904ac07d44997d0c552a13786e2962ad6fe4813b8146e679e" nocase ascii wide
                        $string13_AutoBlue_MS17_010_offensive_tool_keyword = /c\:\\pwned\.txt/ nocase ascii wide
                        $string14_AutoBlue_MS17_010_offensive_tool_keyword = /c\:\\pwned_exec\.txt/ nocase ascii wide
                        $string15_AutoBlue_MS17_010_offensive_tool_keyword = "d71724687c2914d5e68596f5951d1a94fa511dd2cb57f7fbc39f771a6ec43ae7" nocase ascii wide
                        $string16_AutoBlue_MS17_010_offensive_tool_keyword = "echo msfvenom -p windows" nocase ascii wide
                        $string17_AutoBlue_MS17_010_offensive_tool_keyword = "Eternal Blue Windows Shellcode Compiler" nocase ascii wide
                        $string18_AutoBlue_MS17_010_offensive_tool_keyword = /eternalblue_exploit10\.py/ nocase ascii wide
                        $string19_AutoBlue_MS17_010_offensive_tool_keyword = /eternalblue_exploit7\.py/ nocase ascii wide
                        $string20_AutoBlue_MS17_010_offensive_tool_keyword = /eternalblue_exploit8\.py/ nocase ascii wide
                        $string21_AutoBlue_MS17_010_offensive_tool_keyword = /eternalblue_kshellcode_x64\.asm/ nocase ascii wide
                        $string22_AutoBlue_MS17_010_offensive_tool_keyword = /eternalblue_kshellcode_x86\.asm/ nocase ascii wide
                        $string23_AutoBlue_MS17_010_offensive_tool_keyword = /eternalblue_poc\.py/ nocase ascii wide
                        $string24_AutoBlue_MS17_010_offensive_tool_keyword = /eternalblue_sc_merge\.py/ nocase ascii wide
                        $string25_AutoBlue_MS17_010_offensive_tool_keyword = "Generating x64 meterpreter shell" nocase ascii wide
                        $string26_AutoBlue_MS17_010_offensive_tool_keyword = "Generating x86 meterpreter shell" nocase ascii wide
                        $string27_AutoBlue_MS17_010_offensive_tool_keyword = "MERGING SHELLCODE WOOOO!!!" nocase ascii wide
                        $string28_AutoBlue_MS17_010_offensive_tool_keyword = "set PAYLOAD windows/x64/meterpreter_reverse_tcp" nocase ascii wide
                        $string29_AutoBlue_MS17_010_offensive_tool_keyword = "set PAYLOAD windows/x64/shell/reverse_tcp" nocase ascii wide
                        $string30_AutoBlue_MS17_010_offensive_tool_keyword = /You\scan\'t\sCD\sunder\sSMBEXEC\.\sUse\sfull\spaths/ nocase ascii wide
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