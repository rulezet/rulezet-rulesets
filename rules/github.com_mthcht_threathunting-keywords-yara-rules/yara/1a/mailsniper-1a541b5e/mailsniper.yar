rule MailSniper
{
    meta:
        description = "Detection patterns for the tool 'MailSniper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MailSniper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-ExchHostname\s.{0,100}\s\-Password\s/ nocase ascii wide
                        $string2 = " -Remote -ExchHostname " nocase ascii wide
                        $string3 = "/MailSniper/" nocase ascii wide
                        $string4 = "AccessTokenImpersonationAccount" nocase ascii wide
                        $string5 = "dafthack/MailSniper" nocase ascii wide
                        $string6 = "Get-AccessTokenWithPRT" nocase ascii wide
                        $string7 = "Get-ADUsernameFromEWS" nocase ascii wide
                        $string8 = "Get-BaseLineResponseTimeEAS" nocase ascii wide
                        $string9 = "Get-ExchangeAccessToken" nocase ascii wide
                        $string10 = "Get-ExoPsAccessToken" nocase ascii wide
                        $string11 = "Get-HeadersWithPrtCookies" nocase ascii wide
                        $string12 = "Get-UserPRTToken" nocase ascii wide
                        $string13 = "Invoke-DomainHarvest" nocase ascii wide
                        $string14 = "Invoke-DomainHarvestOWA" nocase ascii wide
                        $string15 = "Invoke-GlobalMailSearch" nocase ascii wide
                        $string16 = "Invoke-GlobalMailSearch" nocase ascii wide
                        $string17 = "Invoke-GlobalO365MailSearch" nocase ascii wide
                        $string18 = "Invoke-InjectGEvent" nocase ascii wide
                        $string19 = "Invoke-InjectGEventAPI" nocase ascii wide
                        $string20 = "Invoke-MonitorCredSniper" nocase ascii wide
                        $string21 = "Invoke-OpenInboxFinder" nocase ascii wide
                        $string22 = "Invoke-PasswordSpray" nocase ascii wide
                        $string23 = "Invoke-PasswordSprayEAS" nocase ascii wide
                        $string24 = "Invoke-PasswordSprayEWS" nocase ascii wide
                        $string25 = "Invoke-PasswordSprayGmail" nocase ascii wide
                        $string26 = "Invoke-PasswordSprayOWA" nocase ascii wide
                        $string27 = "Invoke-UsernameHarvestEAS" nocase ascii wide
                        $string28 = "Invoke-UsernameHarvestGmail" nocase ascii wide
                        $string29 = "Invoke-UsernameHarvestOWA" nocase ascii wide
                        $string30 = "LoadEWSDLL" nocase ascii wide
                        $string31 = "MailSniper" nocase ascii wide
                        $string32 = /MailSniper\.ps1/ nocase ascii wide
                        $string33 = "UsePrtAdminAccount" nocase ascii wide
                        $string34 = "UsePrtImperonsationAccount" nocase ascii wide
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