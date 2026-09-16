rule rule_MicroBurst_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MicroBurst' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MicroBurst"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MicroBurst_offensive_tool_keyword = /\/MicroBurst\.git/ nocase ascii wide
                        $string2_MicroBurst_offensive_tool_keyword = /\\Files\\ContainersFileUrls\.txt/ nocase ascii wide
                        $string3_MicroBurst_offensive_tool_keyword = /\\MSOL\\DomainCompanyInfo\.txt/ nocase ascii wide
                        $string4_MicroBurst_offensive_tool_keyword = /\\Resources\\Disks\-NoEncryption\.txt/ nocase ascii wide
                        $string5_MicroBurst_offensive_tool_keyword = /C\:\\dsc_hello\.txt/ nocase ascii wide
                        $string6_MicroBurst_offensive_tool_keyword = /Get\-AzAutomationAccountCredsREST\.ps1/ nocase ascii wide
                        $string7_MicroBurst_offensive_tool_keyword = "Get-AzDomainInfo" nocase ascii wide
                        $string8_MicroBurst_offensive_tool_keyword = /Get\-AzDomainInfoREST\.ps1/ nocase ascii wide
                        $string9_MicroBurst_offensive_tool_keyword = /Get\-AzKeyVaultKeysREST\.ps1/ nocase ascii wide
                        $string10_MicroBurst_offensive_tool_keyword = /Get\-AzKeyVaultSecretsREST\.ps1/ nocase ascii wide
                        $string11_MicroBurst_offensive_tool_keyword = "Get-AzPasswords" nocase ascii wide
                        $string12_MicroBurst_offensive_tool_keyword = /Get\-AZStorageKeysREST\.ps1/ nocase ascii wide
                        $string13_MicroBurst_offensive_tool_keyword = "Get-AzureADDomainInfo" nocase ascii wide
                        $string14_MicroBurst_offensive_tool_keyword = /Get\-AzureADDomainInfo\.ps1/ nocase ascii wide
                        $string15_MicroBurst_offensive_tool_keyword = "Get-AzurePasswords" nocase ascii wide
                        $string16_MicroBurst_offensive_tool_keyword = "Get-AzUserAssignedIdentity" nocase ascii wide
                        $string17_MicroBurst_offensive_tool_keyword = /Invoke\-APIConnectionHijack\.ps1/ nocase ascii wide
                        $string18_MicroBurst_offensive_tool_keyword = "Invoke-AzElevatedAccessToggle" nocase ascii wide
                        $string19_MicroBurst_offensive_tool_keyword = "Invoke-AzRESTBastionShareableLink" nocase ascii wide
                        $string20_MicroBurst_offensive_tool_keyword = /Invoke\-AzureRmVMBulkCMD\.ps1/ nocase ascii wide
                        $string21_MicroBurst_offensive_tool_keyword = /Invoke\-AzVMBulkCMD\.ps1/ nocase ascii wide
                        $string22_MicroBurst_offensive_tool_keyword = /Invoke\-EnumerateAzureBlobs\.ps1/ nocase ascii wide
                        $string23_MicroBurst_offensive_tool_keyword = /Invoke\-EnumerateAzureSubDomains\.ps1/ nocase ascii wide
                        $string24_MicroBurst_offensive_tool_keyword = /MicroBurst\.psm1/ nocase ascii wide
                        $string25_MicroBurst_offensive_tool_keyword = /MicroBurst\-Az\.psm1/ nocase ascii wide
                        $string26_MicroBurst_offensive_tool_keyword = "MicroBurst-AzureAD" nocase ascii wide
                        $string27_MicroBurst_offensive_tool_keyword = "MicroBurst-AzureREST" nocase ascii wide
                        $string28_MicroBurst_offensive_tool_keyword = "MicroBurst-AzureRM" nocase ascii wide
                        $string29_MicroBurst_offensive_tool_keyword = "MicroBurst-master" nocase ascii wide
                        $string30_MicroBurst_offensive_tool_keyword = /MicroBurst\-Misc\.psm1/ nocase ascii wide
                        $string31_MicroBurst_offensive_tool_keyword = "MicroBurst-MSOL" nocase ascii wide
                        $string32_MicroBurst_offensive_tool_keyword = /OwnerPersist\-POST\./ nocase ascii wide
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