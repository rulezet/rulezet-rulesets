rule PowershellTools
{
    meta:
        description = "Detection patterns for the tool 'PowershellTools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowershellTools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPowerTools\.ps1/ nocase ascii wide
                        $string2 = /\sQuickViewAD\.ps1/ nocase ascii wide
                        $string3 = /\.exe\sasktgs\s\/ticket\:B64_TGT\s\/service\:/ nocase ascii wide
                        $string4 = /\.exe\ssilver\s\/sids\:.{0,1000}\/target\:/ nocase ascii wide
                        $string5 = /\/PowershellTools\.git/ nocase ascii wide
                        $string6 = /\/PowerTools\.ps1/ nocase ascii wide
                        $string7 = /\/QuickViewAD\.ps1/ nocase ascii wide
                        $string8 = /\\PowerTools\.ps1/ nocase ascii wide
                        $string9 = /\\QuickViewAD\.ps1/ nocase ascii wide
                        $string10 = /C\:\\Temp\\.{0,1000}\-.{0,1000}\.kirbi/ nocase ascii wide
                        $string11 = "Find-ADInterestingACL " nocase ascii wide
                        $string12 = /Find\-ADInterestingACL\.ps1/ nocase ascii wide
                        $string13 = "Get-NestedGroupMembership " nocase ascii wide
                        $string14 = /Get\-NestedGroupMembership\.ps1/ nocase ascii wide
                        $string15 = /Get\-TrustTicket\.ps1/ nocase ascii wide
                        $string16 = "gustanini/PowershellTools" nocase ascii wide
                        $string17 = "Invoke-AccessCheck -PSRemoting" nocase ascii wide
                        $string18 = "Invoke-AccessCheck -SMB" nocase ascii wide
                        $string19 = /Invoke\-AccessCheck\.ps1/ nocase ascii wide
                        $string20 = "kerberos::golden /service:" nocase ascii wide
                        $string21 = /PowershellTools\-main\.zip/ nocase ascii wide
                        $string22 = "Set-MacroSecurityOff " nocase ascii wide
                        $string23 = /Set\-MacroSecurityOff\.ps1/ nocase ascii wide
                        $string24 = "tgs::ask /tgt:" nocase ascii wide

    condition:
        any of them
}