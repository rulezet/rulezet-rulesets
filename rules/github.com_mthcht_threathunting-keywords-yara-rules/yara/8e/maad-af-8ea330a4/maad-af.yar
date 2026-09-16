rule MAAD_AF
{
    meta:
        description = "Detection patterns for the tool 'MAAD-AF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MAAD-AF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/MAAD\-AF\.git/ nocase ascii wide
                        $string2 = /\\Tor\\tor\.exe/ nocase ascii wide
                        $string3 = /\\Tor\\torrc/ nocase ascii wide
                        $string4 = /\\TorBrowser/ nocase ascii wide
                        $string5 = /AzureADRecon\.ps1/ nocase ascii wide
                        $string6 = "Brute-force Unsuccessful!" nocase ascii wide
                        $string7 = /BruteForce\.ps1/ nocase ascii wide
                        $string8 = /CrossTenantSynchronizationBackdoor\.ps1/ nocase ascii wide
                        $string9 = "--defaults-torrc" nocase ascii wide
                        $string10 = "DisableAntiPhishing" nocase ascii wide
                        $string11 = /DisableAntiPhishing\.ps1/ nocase ascii wide
                        $string12 = /DisableMailboxAuditing\.ps1/ nocase ascii wide
                        $string13 = /DisableMFA\.ps1/ nocase ascii wide
                        $string14 = /ExternalRecon\.ps1/ nocase ascii wide
                        $string15 = /GrantMailboxAccess\.ps1/ nocase ascii wide
                        $string16 = /Initial_Access\.ps1/ nocase ascii wide
                        $string17 = /LaunchExploitMode\.ps1/ nocase ascii wide
                        $string18 = /LaunchPreCompromise\.ps1/ nocase ascii wide
                        $string19 = /MAAD_Attack\.ps1/ nocase ascii wide
                        $string20 = /MAAD_Config\.ps1/ nocase ascii wide
                        $string21 = /MAAD_Mitre_Map\.ps1/ nocase ascii wide
                        $string22 = /MAADInitialization\.ps1/ nocase ascii wide
                        $string23 = /NewAdminAccountCreation\.ps1/ nocase ascii wide
                        $string24 = /ReconUserGroupRoles\.ps1/ nocase ascii wide
                        $string25 = /SharepointExploiter\.ps1/ nocase ascii wide
                        $string26 = /SharepointSiteExploiter\.ps1/ nocase ascii wide
                        $string27 = "Successfully cracked account password" nocase ascii wide
                        $string28 = /TORAnonymizer\.ps1/ nocase ascii wide
                        $string29 = "vectra-ai-research/MAAD-AF" nocase ascii wide

    condition:
        any of them
}