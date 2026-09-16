rule Invoke_ADEnum
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ADEnum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ADEnum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -Recommended -SprayEmptyPasswords" nocase ascii wide
                        $string2 = /\$EmptyPasswordUsers/ nocase ascii wide
                        $string3 = /\$PotentialComputersWithEmptyPassword/ nocase ascii wide
                        $string4 = /\$PotentialUsersWithEmptyPassword/ nocase ascii wide
                        $string5 = /\$SprayEmptyPasswords/ nocase ascii wide
                        $string6 = /\/Invoke\-ADEnum\.git/ nocase ascii wide
                        $string7 = /\\.{0,1000}_AD\-Audit_.{0,1000}\.txt/ nocase ascii wide
                        $string8 = /\\Invoke\-ADEnum\\/ nocase ascii wide
                        $string9 = /\\Invoke\-ADEnum\-main/ nocase ascii wide
                        $string10 = /\\krbtgtAccounts\.json/ nocase ascii wide
                        $string11 = /\]\sCollecting\sKrbtgt/ nocase ascii wide
                        $string12 = "27049d9f4a7125e9be92e84edcad5dc118bc8503920fb3250b3e2f7577370b49" nocase ascii wide
                        $string13 = "Find-LocalAdminAccess " nocase ascii wide
                        $string14 = "Invoke-ADEnum -" nocase ascii wide
                        $string15 = /Invoke\-ADEnum\.ps1/ nocase ascii wide
                        $string16 = "Invoke-ShareHunter " nocase ascii wide
                        $string17 = "Leo4j/Invoke-ADEnum" nocase ascii wide

    condition:
        any of them
}