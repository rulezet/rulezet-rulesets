rule rule_Azure_AccessPermissions_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Azure-AccessPermissions' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azure-AccessPermissions"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Azure_AccessPermissions_offensive_tool_keyword = /\/Azure\-AccessPermissions\.git/ nocase ascii wide
                        $string2_Azure_AccessPermissions_offensive_tool_keyword = "AAP-AddToHighPrivilegePrincipalMap" nocase ascii wide
                        $string3_Azure_AccessPermissions_offensive_tool_keyword = "AAP-CheckIfMemberOfPrivilegedDirectoryRole" nocase ascii wide
                        $string4_Azure_AccessPermissions_offensive_tool_keyword = "AAP-DisplayApplicableMFAConditionalAccessPolicyForUserID" nocase ascii wide
                        $string5_Azure_AccessPermissions_offensive_tool_keyword = "AAP-DisplayHighPrivilegePrincipalMap" nocase ascii wide
                        $string6_Azure_AccessPermissions_offensive_tool_keyword = "AAP-DisplayNonHighPrivilegedRoleAssignments" nocase ascii wide
                        $string7_Azure_AccessPermissions_offensive_tool_keyword = "AAP-GetHighPrivilegedDirectoryRoleTemplateMap" nocase ascii wide
                        $string8_Azure_AccessPermissions_offensive_tool_keyword = /Azure\-AccessPermissions\.ps1/ nocase ascii wide
                        $string9_Azure_AccessPermissions_offensive_tool_keyword = "Azure-AccessPermissions-master" nocase ascii wide
                        $string10_Azure_AccessPermissions_offensive_tool_keyword = "csandker/Azure-AccessPermissions" nocase ascii wide
                        $string11_Azure_AccessPermissions_offensive_tool_keyword = "Enumerate-AllHighPrivilegePrincipals" nocase ascii wide
                        $string12_Azure_AccessPermissions_offensive_tool_keyword = "Enumerate-MFAStatusOfHighPrivilegePrincipals" nocase ascii wide
                        $string13_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForAllGroups" nocase ascii wide
                        $string14_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForAllServicePrincipals" nocase ascii wide
                        $string15_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForAllUsers" nocase ascii wide
                        $string16_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForCurrentUser" nocase ascii wide
                        $string17_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForCurrentUser" nocase ascii wide
                        $string18_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForGroup" nocase ascii wide
                        $string19_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForServicePrincipal" nocase ascii wide
                        $string20_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForUser" nocase ascii wide
                        $string21_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AllAccessChecks" nocase ascii wide

    condition:
        any of them
}