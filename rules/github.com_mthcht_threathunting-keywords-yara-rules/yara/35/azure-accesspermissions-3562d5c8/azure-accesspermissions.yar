rule Azure_AccessPermissions
{
    meta:
        description = "Detection patterns for the tool 'Azure-AccessPermissions' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azure-AccessPermissions"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Azure\-AccessPermissions\.git/ nocase ascii wide
                        $string2 = "AAP-AddToHighPrivilegePrincipalMap" nocase ascii wide
                        $string3 = "AAP-CheckIfMemberOfPrivilegedDirectoryRole" nocase ascii wide
                        $string4 = "AAP-DisplayApplicableMFAConditionalAccessPolicyForUserID" nocase ascii wide
                        $string5 = "AAP-DisplayHighPrivilegePrincipalMap" nocase ascii wide
                        $string6 = "AAP-DisplayNonHighPrivilegedRoleAssignments" nocase ascii wide
                        $string7 = "AAP-GetHighPrivilegedDirectoryRoleTemplateMap" nocase ascii wide
                        $string8 = /Azure\-AccessPermissions\.ps1/ nocase ascii wide
                        $string9 = "Azure-AccessPermissions-master" nocase ascii wide
                        $string10 = "csandker/Azure-AccessPermissions" nocase ascii wide
                        $string11 = "Enumerate-AllHighPrivilegePrincipals" nocase ascii wide
                        $string12 = "Enumerate-MFAStatusOfHighPrivilegePrincipals" nocase ascii wide
                        $string13 = "Invoke-AccessCheckForAllGroups" nocase ascii wide
                        $string14 = "Invoke-AccessCheckForAllServicePrincipals" nocase ascii wide
                        $string15 = "Invoke-AccessCheckForAllUsers" nocase ascii wide
                        $string16 = "Invoke-AccessCheckForCurrentUser" nocase ascii wide
                        $string17 = "Invoke-AccessCheckForCurrentUser" nocase ascii wide
                        $string18 = "Invoke-AccessCheckForGroup" nocase ascii wide
                        $string19 = "Invoke-AccessCheckForServicePrincipal" nocase ascii wide
                        $string20 = "Invoke-AccessCheckForUser" nocase ascii wide
                        $string21 = "Invoke-AllAccessChecks" nocase ascii wide

    condition:
        any of them
}