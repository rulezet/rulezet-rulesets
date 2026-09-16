rule rule_adPEAS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adPEAS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adPEAS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adPEAS_offensive_tool_keyword = /\sadPEAS\.ps1/ nocase ascii wide
                        $string2_adPEAS_offensive_tool_keyword = /\sadPEAS_DomainPolicy\.Sys/ nocase ascii wide
                        $string3_adPEAS_offensive_tool_keyword = /\sadPEAS_out\.txt/ nocase ascii wide
                        $string4_adPEAS_offensive_tool_keyword = /\sadPEAS\-Light\.ps1/ nocase ascii wide
                        $string5_adPEAS_offensive_tool_keyword = " -Module Bloodhound -Method All" nocase ascii wide
                        $string6_adPEAS_offensive_tool_keyword = " -Module Bloodhound -Scope All" nocase ascii wide
                        $string7_adPEAS_offensive_tool_keyword = /\$adPEAS_/ nocase ascii wide
                        $string8_adPEAS_offensive_tool_keyword = /\/adPEAS\.git/ nocase ascii wide
                        $string9_adPEAS_offensive_tool_keyword = /\/adPEAS\.ps1/ nocase ascii wide
                        $string10_adPEAS_offensive_tool_keyword = /\/adPEAS\-Light\.ps1/ nocase ascii wide
                        $string11_adPEAS_offensive_tool_keyword = /\\adPEAS\.ps1/ nocase ascii wide
                        $string12_adPEAS_offensive_tool_keyword = /\\adPEAS_DomainPolicy\.Sys/ nocase ascii wide
                        $string13_adPEAS_offensive_tool_keyword = /\\adPEAS_outputfile/ nocase ascii wide
                        $string14_adPEAS_offensive_tool_keyword = /\\adPEAS\-Light\.ps1/ nocase ascii wide
                        $string15_adPEAS_offensive_tool_keyword = /\\adPEAS\-main/ nocase ascii wide
                        $string16_adPEAS_offensive_tool_keyword = /\\adPEAS\-master/ nocase ascii wide
                        $string17_adPEAS_offensive_tool_keyword = "61106960/adPEAS" nocase ascii wide
                        $string18_adPEAS_offensive_tool_keyword = "6f919785361c350dd35b21573e02f681806645c50da3e98ddc703d2efa838dd6" nocase ascii wide
                        $string19_adPEAS_offensive_tool_keyword = "97f7f1ee8228a28173f07062e712dfaa25f64cfcf443a7f1d26c9502f6046b50" nocase ascii wide
                        $string20_adPEAS_offensive_tool_keyword = "Get-adPEASAccounts" nocase ascii wide
                        $string21_adPEAS_offensive_tool_keyword = "Get-adPEASADCS" nocase ascii wide
                        $string22_adPEAS_offensive_tool_keyword = "Get-adPEASBloodhound" nocase ascii wide
                        $string23_adPEAS_offensive_tool_keyword = "Get-adPEASComputer" nocase ascii wide
                        $string24_adPEAS_offensive_tool_keyword = "Get-adPEASCreds" nocase ascii wide
                        $string25_adPEAS_offensive_tool_keyword = "Get-adPEASDelegation" nocase ascii wide
                        $string26_adPEAS_offensive_tool_keyword = "Get-adPEASDomain" nocase ascii wide
                        $string27_adPEAS_offensive_tool_keyword = "Get-adPEASGPO" nocase ascii wide
                        $string28_adPEAS_offensive_tool_keyword = "Get-adPEASRights" nocase ascii wide
                        $string29_adPEAS_offensive_tool_keyword = "Get-WMIRegProxy" nocase ascii wide
                        $string30_adPEAS_offensive_tool_keyword = "Invoke-adPEAS" nocase ascii wide
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