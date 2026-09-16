rule rule_PowershellTools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowershellTools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowershellTools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowershellTools_offensive_tool_keyword = /\sPowerTools\.ps1/ nocase ascii wide
                        $string2_PowershellTools_offensive_tool_keyword = /\sQuickViewAD\.ps1/ nocase ascii wide
                        $string3_PowershellTools_offensive_tool_keyword = /\.exe\sasktgs\s\/ticket\:B64_TGT\s\/service\:/ nocase ascii wide
                        $string4_PowershellTools_offensive_tool_keyword = /\.exe\ssilver\s\/sids\:.{0,1000}\/target\:/ nocase ascii wide
                        $string5_PowershellTools_offensive_tool_keyword = /\/PowershellTools\.git/ nocase ascii wide
                        $string6_PowershellTools_offensive_tool_keyword = /\/PowerTools\.ps1/ nocase ascii wide
                        $string7_PowershellTools_offensive_tool_keyword = /\/QuickViewAD\.ps1/ nocase ascii wide
                        $string8_PowershellTools_offensive_tool_keyword = /\\PowerTools\.ps1/ nocase ascii wide
                        $string9_PowershellTools_offensive_tool_keyword = /\\QuickViewAD\.ps1/ nocase ascii wide
                        $string10_PowershellTools_offensive_tool_keyword = /C\:\\Temp\\.{0,1000}\-.{0,1000}\.kirbi/ nocase ascii wide
                        $string11_PowershellTools_offensive_tool_keyword = "Find-ADInterestingACL " nocase ascii wide
                        $string12_PowershellTools_offensive_tool_keyword = /Find\-ADInterestingACL\.ps1/ nocase ascii wide
                        $string13_PowershellTools_offensive_tool_keyword = "Get-NestedGroupMembership " nocase ascii wide
                        $string14_PowershellTools_offensive_tool_keyword = /Get\-NestedGroupMembership\.ps1/ nocase ascii wide
                        $string15_PowershellTools_offensive_tool_keyword = /Get\-TrustTicket\.ps1/ nocase ascii wide
                        $string16_PowershellTools_offensive_tool_keyword = "gustanini/PowershellTools" nocase ascii wide
                        $string17_PowershellTools_offensive_tool_keyword = "Invoke-AccessCheck -PSRemoting" nocase ascii wide
                        $string18_PowershellTools_offensive_tool_keyword = "Invoke-AccessCheck -SMB" nocase ascii wide
                        $string19_PowershellTools_offensive_tool_keyword = /Invoke\-AccessCheck\.ps1/ nocase ascii wide
                        $string20_PowershellTools_offensive_tool_keyword = "kerberos::golden /service:" nocase ascii wide
                        $string21_PowershellTools_offensive_tool_keyword = /PowershellTools\-main\.zip/ nocase ascii wide
                        $string22_PowershellTools_offensive_tool_keyword = "Set-MacroSecurityOff " nocase ascii wide
                        $string23_PowershellTools_offensive_tool_keyword = /Set\-MacroSecurityOff\.ps1/ nocase ascii wide
                        $string24_PowershellTools_offensive_tool_keyword = "tgs::ask /tgt:" nocase ascii wide

    condition:
        any of them
}