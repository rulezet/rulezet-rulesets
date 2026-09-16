rule MicroBurst
{
    meta:
        description = "Detection patterns for the tool 'MicroBurst' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MicroBurst"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/MicroBurst\.git/ nocase ascii wide
                        $string2 = /\\Files\\ContainersFileUrls\.txt/ nocase ascii wide
                        $string3 = /\\MSOL\\DomainCompanyInfo\.txt/ nocase ascii wide
                        $string4 = /\\Resources\\Disks\-NoEncryption\.txt/ nocase ascii wide
                        $string5 = /C\:\\dsc_hello\.txt/ nocase ascii wide
                        $string6 = /Get\-AzAutomationAccountCredsREST\.ps1/ nocase ascii wide
                        $string7 = "Get-AzDomainInfo" nocase ascii wide
                        $string8 = /Get\-AzDomainInfoREST\.ps1/ nocase ascii wide
                        $string9 = /Get\-AzKeyVaultKeysREST\.ps1/ nocase ascii wide
                        $string10 = /Get\-AzKeyVaultSecretsREST\.ps1/ nocase ascii wide
                        $string11 = "Get-AzPasswords" nocase ascii wide
                        $string12 = /Get\-AZStorageKeysREST\.ps1/ nocase ascii wide
                        $string13 = "Get-AzureADDomainInfo" nocase ascii wide
                        $string14 = /Get\-AzureADDomainInfo\.ps1/ nocase ascii wide
                        $string15 = "Get-AzurePasswords" nocase ascii wide
                        $string16 = "Get-AzUserAssignedIdentity" nocase ascii wide
                        $string17 = /Invoke\-APIConnectionHijack\.ps1/ nocase ascii wide
                        $string18 = "Invoke-AzElevatedAccessToggle" nocase ascii wide
                        $string19 = "Invoke-AzRESTBastionShareableLink" nocase ascii wide
                        $string20 = /Invoke\-AzureRmVMBulkCMD\.ps1/ nocase ascii wide
                        $string21 = /Invoke\-AzVMBulkCMD\.ps1/ nocase ascii wide
                        $string22 = /Invoke\-EnumerateAzureBlobs\.ps1/ nocase ascii wide
                        $string23 = /Invoke\-EnumerateAzureSubDomains\.ps1/ nocase ascii wide
                        $string24 = /MicroBurst\.psm1/ nocase ascii wide
                        $string25 = /MicroBurst\-Az\.psm1/ nocase ascii wide
                        $string26 = "MicroBurst-AzureAD" nocase ascii wide
                        $string27 = "MicroBurst-AzureREST" nocase ascii wide
                        $string28 = "MicroBurst-AzureRM" nocase ascii wide
                        $string29 = "MicroBurst-master" nocase ascii wide
                        $string30 = /MicroBurst\-Misc\.psm1/ nocase ascii wide
                        $string31 = "MicroBurst-MSOL" nocase ascii wide
                        $string32 = /OwnerPersist\-POST\./ nocase ascii wide
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