rule rule_Invoke_ADEnum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ADEnum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ADEnum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_ADEnum_offensive_tool_keyword = " -Recommended -SprayEmptyPasswords" nocase ascii wide
                        $string2_Invoke_ADEnum_offensive_tool_keyword = /\$EmptyPasswordUsers/ nocase ascii wide
                        $string3_Invoke_ADEnum_offensive_tool_keyword = /\$PotentialComputersWithEmptyPassword/ nocase ascii wide
                        $string4_Invoke_ADEnum_offensive_tool_keyword = /\$PotentialUsersWithEmptyPassword/ nocase ascii wide
                        $string5_Invoke_ADEnum_offensive_tool_keyword = /\$SprayEmptyPasswords/ nocase ascii wide
                        $string6_Invoke_ADEnum_offensive_tool_keyword = /\/Invoke\-ADEnum\.git/ nocase ascii wide
                        $string7_Invoke_ADEnum_offensive_tool_keyword = /\\.{0,1000}_AD\-Audit_.{0,1000}\.txt/ nocase ascii wide
                        $string8_Invoke_ADEnum_offensive_tool_keyword = /\\Invoke\-ADEnum\\/ nocase ascii wide
                        $string9_Invoke_ADEnum_offensive_tool_keyword = /\\Invoke\-ADEnum\-main/ nocase ascii wide
                        $string10_Invoke_ADEnum_offensive_tool_keyword = /\\krbtgtAccounts\.json/ nocase ascii wide
                        $string11_Invoke_ADEnum_offensive_tool_keyword = /\]\sCollecting\sKrbtgt/ nocase ascii wide
                        $string12_Invoke_ADEnum_offensive_tool_keyword = "27049d9f4a7125e9be92e84edcad5dc118bc8503920fb3250b3e2f7577370b49" nocase ascii wide
                        $string13_Invoke_ADEnum_offensive_tool_keyword = "Find-LocalAdminAccess " nocase ascii wide
                        $string14_Invoke_ADEnum_offensive_tool_keyword = "Invoke-ADEnum -" nocase ascii wide
                        $string15_Invoke_ADEnum_offensive_tool_keyword = /Invoke\-ADEnum\.ps1/ nocase ascii wide
                        $string16_Invoke_ADEnum_offensive_tool_keyword = "Invoke-ShareHunter " nocase ascii wide
                        $string17_Invoke_ADEnum_offensive_tool_keyword = "Leo4j/Invoke-ADEnum" nocase ascii wide

    condition:
        any of them
}