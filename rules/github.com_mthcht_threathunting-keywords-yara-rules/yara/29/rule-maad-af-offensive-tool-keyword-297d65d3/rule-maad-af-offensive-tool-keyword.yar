rule rule_MAAD_AF_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MAAD-AF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MAAD-AF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MAAD_AF_offensive_tool_keyword = /\/MAAD\-AF\.git/ nocase ascii wide
                        $string2_MAAD_AF_offensive_tool_keyword = /\\Tor\\tor\.exe/ nocase ascii wide
                        $string3_MAAD_AF_offensive_tool_keyword = /\\Tor\\torrc/ nocase ascii wide
                        $string4_MAAD_AF_offensive_tool_keyword = /\\TorBrowser/ nocase ascii wide
                        $string5_MAAD_AF_offensive_tool_keyword = /AzureADRecon\.ps1/ nocase ascii wide
                        $string6_MAAD_AF_offensive_tool_keyword = "Brute-force Unsuccessful!" nocase ascii wide
                        $string7_MAAD_AF_offensive_tool_keyword = /BruteForce\.ps1/ nocase ascii wide
                        $string8_MAAD_AF_offensive_tool_keyword = /CrossTenantSynchronizationBackdoor\.ps1/ nocase ascii wide
                        $string9_MAAD_AF_offensive_tool_keyword = "--defaults-torrc" nocase ascii wide
                        $string10_MAAD_AF_offensive_tool_keyword = "DisableAntiPhishing" nocase ascii wide
                        $string11_MAAD_AF_offensive_tool_keyword = /DisableAntiPhishing\.ps1/ nocase ascii wide
                        $string12_MAAD_AF_offensive_tool_keyword = /DisableMailboxAuditing\.ps1/ nocase ascii wide
                        $string13_MAAD_AF_offensive_tool_keyword = /DisableMFA\.ps1/ nocase ascii wide
                        $string14_MAAD_AF_offensive_tool_keyword = /ExternalRecon\.ps1/ nocase ascii wide
                        $string15_MAAD_AF_offensive_tool_keyword = /GrantMailboxAccess\.ps1/ nocase ascii wide
                        $string16_MAAD_AF_offensive_tool_keyword = /Initial_Access\.ps1/ nocase ascii wide
                        $string17_MAAD_AF_offensive_tool_keyword = /LaunchExploitMode\.ps1/ nocase ascii wide
                        $string18_MAAD_AF_offensive_tool_keyword = /LaunchPreCompromise\.ps1/ nocase ascii wide
                        $string19_MAAD_AF_offensive_tool_keyword = /MAAD_Attack\.ps1/ nocase ascii wide
                        $string20_MAAD_AF_offensive_tool_keyword = /MAAD_Config\.ps1/ nocase ascii wide
                        $string21_MAAD_AF_offensive_tool_keyword = /MAAD_Mitre_Map\.ps1/ nocase ascii wide
                        $string22_MAAD_AF_offensive_tool_keyword = /MAADInitialization\.ps1/ nocase ascii wide
                        $string23_MAAD_AF_offensive_tool_keyword = /NewAdminAccountCreation\.ps1/ nocase ascii wide
                        $string24_MAAD_AF_offensive_tool_keyword = /ReconUserGroupRoles\.ps1/ nocase ascii wide
                        $string25_MAAD_AF_offensive_tool_keyword = /SharepointExploiter\.ps1/ nocase ascii wide
                        $string26_MAAD_AF_offensive_tool_keyword = /SharepointSiteExploiter\.ps1/ nocase ascii wide
                        $string27_MAAD_AF_offensive_tool_keyword = "Successfully cracked account password" nocase ascii wide
                        $string28_MAAD_AF_offensive_tool_keyword = /TORAnonymizer\.ps1/ nocase ascii wide
                        $string29_MAAD_AF_offensive_tool_keyword = "vectra-ai-research/MAAD-AF" nocase ascii wide
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