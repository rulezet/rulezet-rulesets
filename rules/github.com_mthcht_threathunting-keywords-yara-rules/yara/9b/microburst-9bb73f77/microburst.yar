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

    condition:
        any of them
}