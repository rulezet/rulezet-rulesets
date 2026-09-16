rule adPEAS
{
    meta:
        description = "Detection patterns for the tool 'adPEAS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adPEAS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sadPEAS\.ps1/ nocase ascii wide
                        $string2 = /\sadPEAS_DomainPolicy\.Sys/ nocase ascii wide
                        $string3 = /\sadPEAS_out\.txt/ nocase ascii wide
                        $string4 = /\sadPEAS\-Light\.ps1/ nocase ascii wide
                        $string5 = " -Module Bloodhound -Method All" nocase ascii wide
                        $string6 = " -Module Bloodhound -Scope All" nocase ascii wide
                        $string7 = /\$adPEAS_/ nocase ascii wide
                        $string8 = /\/adPEAS\.git/ nocase ascii wide
                        $string9 = /\/adPEAS\.ps1/ nocase ascii wide
                        $string10 = /\/adPEAS\-Light\.ps1/ nocase ascii wide
                        $string11 = /\\adPEAS\.ps1/ nocase ascii wide
                        $string12 = /\\adPEAS_DomainPolicy\.Sys/ nocase ascii wide
                        $string13 = /\\adPEAS_outputfile/ nocase ascii wide
                        $string14 = /\\adPEAS\-Light\.ps1/ nocase ascii wide
                        $string15 = /\\adPEAS\-main/ nocase ascii wide
                        $string16 = /\\adPEAS\-master/ nocase ascii wide
                        $string17 = "61106960/adPEAS" nocase ascii wide
                        $string18 = "6f919785361c350dd35b21573e02f681806645c50da3e98ddc703d2efa838dd6" nocase ascii wide
                        $string19 = "97f7f1ee8228a28173f07062e712dfaa25f64cfcf443a7f1d26c9502f6046b50" nocase ascii wide
                        $string20 = "Get-adPEASAccounts" nocase ascii wide
                        $string21 = "Get-adPEASADCS" nocase ascii wide
                        $string22 = "Get-adPEASBloodhound" nocase ascii wide
                        $string23 = "Get-adPEASComputer" nocase ascii wide
                        $string24 = "Get-adPEASCreds" nocase ascii wide
                        $string25 = "Get-adPEASDelegation" nocase ascii wide
                        $string26 = "Get-adPEASDomain" nocase ascii wide
                        $string27 = "Get-adPEASGPO" nocase ascii wide
                        $string28 = "Get-adPEASRights" nocase ascii wide
                        $string29 = "Get-WMIRegProxy" nocase ascii wide
                        $string30 = "Invoke-adPEAS" nocase ascii wide

    condition:
        any of them
}