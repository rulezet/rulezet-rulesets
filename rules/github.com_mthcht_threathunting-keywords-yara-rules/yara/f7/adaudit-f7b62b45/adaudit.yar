rule adaudit
{
    meta:
        description = "Detection patterns for the tool 'adaudit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adaudit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sADAudit\.ps1/ nocase ascii wide
                        $string2 = /\/adaudit\.git/ nocase ascii wide
                        $string3 = /\/ADAudit\.ps1/ nocase ascii wide
                        $string4 = /\[\!\]\sYou\shave\sDCs\swith\sRC4\sor\sDES\sallowed\sfor\sKerberos\!\!\!/ nocase ascii wide
                        $string5 = /\\accounts_passdontexpire\.txt/ nocase ascii wide
                        $string6 = /\\ADAudit\.ps1/ nocase ascii wide
                        $string7 = /\\dangerousACL_Computer\.txt/ nocase ascii wide
                        $string8 = /\\dangerousACL_Groups\.txt/ nocase ascii wide
                        $string9 = /\\dcs_weak_kerberos_ciphersuite\.txt/ nocase ascii wide
                        $string10 = /\\domain_admins\.txt/ nocase ascii wide
                        $string11 = /\\enterprise_admins\.txt/ nocase ascii wide
                        $string12 = /\]\sCheck\sfor\sADCS\sVulnerabilities/ nocase ascii wide
                        $string13 = "5f871566a9113e31357e084743f12b74b7199019e66cd10847b61b5666ecf9b1" nocase ascii wide
                        $string14 = "Find-DangerousACLPermissions" nocase ascii wide
                        $string15 = "Get-AccountPassDontExpire" nocase ascii wide
                        $string16 = "Get-ADCSVulns" nocase ascii wide
                        $string17 = "Get-ADUsersWithoutPreAuth" nocase ascii wide
                        $string18 = "Get-DCsNotOwnedByDA" nocase ascii wide
                        $string19 = "Get-GPOEnum" nocase ascii wide
                        $string20 = "Get-GPOsPerOU" nocase ascii wide
                        $string21 = "Get-GPOtoFile" nocase ascii wide
                        $string22 = /Get\-GPPPassword\./ nocase ascii wide
                        $string23 = "Get-NTDSdit" nocase ascii wide
                        $string24 = "Get-PrivilegedGroupAccounts" nocase ascii wide
                        $string25 = "Get-PrivilegedGroupMembership" nocase ascii wide
                        $string26 = "Kerberoast Attack - Services Configured With a Weak Password" nocase ascii wide
                        $string27 = "phillips321/adaudit" nocase ascii wide
                        $string28 = "Write-Nessus-Finding" nocase ascii wide
                        $string29 = "Write-Nessus-Footer" nocase ascii wide
                        $string30 = "Write-Nessus-Header" nocase ascii wide

    condition:
        any of them
}