rule rule_MailSniper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MailSniper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MailSniper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MailSniper_offensive_tool_keyword = /\s\-ExchHostname\s.{0,100}\s\-Password\s/ nocase ascii wide
                        $string2_MailSniper_offensive_tool_keyword = " -Remote -ExchHostname " nocase ascii wide
                        $string3_MailSniper_offensive_tool_keyword = "/MailSniper/" nocase ascii wide
                        $string4_MailSniper_offensive_tool_keyword = "AccessTokenImpersonationAccount" nocase ascii wide
                        $string5_MailSniper_offensive_tool_keyword = "dafthack/MailSniper" nocase ascii wide
                        $string6_MailSniper_offensive_tool_keyword = "Get-AccessTokenWithPRT" nocase ascii wide
                        $string7_MailSniper_offensive_tool_keyword = "Get-ADUsernameFromEWS" nocase ascii wide
                        $string8_MailSniper_offensive_tool_keyword = "Get-BaseLineResponseTimeEAS" nocase ascii wide
                        $string9_MailSniper_offensive_tool_keyword = "Get-ExchangeAccessToken" nocase ascii wide
                        $string10_MailSniper_offensive_tool_keyword = "Get-ExoPsAccessToken" nocase ascii wide
                        $string11_MailSniper_offensive_tool_keyword = "Get-HeadersWithPrtCookies" nocase ascii wide
                        $string12_MailSniper_offensive_tool_keyword = "Get-UserPRTToken" nocase ascii wide
                        $string13_MailSniper_offensive_tool_keyword = "Invoke-DomainHarvest" nocase ascii wide
                        $string14_MailSniper_offensive_tool_keyword = "Invoke-DomainHarvestOWA" nocase ascii wide
                        $string15_MailSniper_offensive_tool_keyword = "Invoke-GlobalMailSearch" nocase ascii wide
                        $string16_MailSniper_offensive_tool_keyword = "Invoke-GlobalMailSearch" nocase ascii wide
                        $string17_MailSniper_offensive_tool_keyword = "Invoke-GlobalO365MailSearch" nocase ascii wide
                        $string18_MailSniper_offensive_tool_keyword = "Invoke-InjectGEvent" nocase ascii wide
                        $string19_MailSniper_offensive_tool_keyword = "Invoke-InjectGEventAPI" nocase ascii wide
                        $string20_MailSniper_offensive_tool_keyword = "Invoke-MonitorCredSniper" nocase ascii wide
                        $string21_MailSniper_offensive_tool_keyword = "Invoke-OpenInboxFinder" nocase ascii wide
                        $string22_MailSniper_offensive_tool_keyword = "Invoke-PasswordSpray" nocase ascii wide
                        $string23_MailSniper_offensive_tool_keyword = "Invoke-PasswordSprayEAS" nocase ascii wide
                        $string24_MailSniper_offensive_tool_keyword = "Invoke-PasswordSprayEWS" nocase ascii wide
                        $string25_MailSniper_offensive_tool_keyword = "Invoke-PasswordSprayGmail" nocase ascii wide
                        $string26_MailSniper_offensive_tool_keyword = "Invoke-PasswordSprayOWA" nocase ascii wide
                        $string27_MailSniper_offensive_tool_keyword = "Invoke-UsernameHarvestEAS" nocase ascii wide
                        $string28_MailSniper_offensive_tool_keyword = "Invoke-UsernameHarvestGmail" nocase ascii wide
                        $string29_MailSniper_offensive_tool_keyword = "Invoke-UsernameHarvestOWA" nocase ascii wide
                        $string30_MailSniper_offensive_tool_keyword = "LoadEWSDLL" nocase ascii wide
                        $string31_MailSniper_offensive_tool_keyword = "MailSniper" nocase ascii wide
                        $string32_MailSniper_offensive_tool_keyword = /MailSniper\.ps1/ nocase ascii wide
                        $string33_MailSniper_offensive_tool_keyword = "UsePrtAdminAccount" nocase ascii wide
                        $string34_MailSniper_offensive_tool_keyword = "UsePrtImperonsationAccount" nocase ascii wide
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