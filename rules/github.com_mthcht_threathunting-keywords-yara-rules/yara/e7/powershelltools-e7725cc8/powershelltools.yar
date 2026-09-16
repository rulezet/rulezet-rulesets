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
                        $string4 = /\.exe\ssilver\s\/sids\:.{0,100}\/target\:/ nocase ascii wide
                        $string5 = /\/PowershellTools\.git/ nocase ascii wide
                        $string6 = /\/PowerTools\.ps1/ nocase ascii wide
                        $string7 = /\/QuickViewAD\.ps1/ nocase ascii wide
                        $string8 = /\\PowerTools\.ps1/ nocase ascii wide
                        $string9 = /\\QuickViewAD\.ps1/ nocase ascii wide
                        $string10 = /C\:\\Temp\\.{0,100}\-.{0,100}\.kirbi/ nocase ascii wide
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