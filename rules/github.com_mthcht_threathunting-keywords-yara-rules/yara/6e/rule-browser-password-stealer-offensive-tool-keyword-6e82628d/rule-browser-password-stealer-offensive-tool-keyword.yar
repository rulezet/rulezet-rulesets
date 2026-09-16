rule rule_Browser_password_stealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Browser-password-stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser-password-stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Browser_password_stealer_offensive_tool_keyword = /\schromium_based_browsers\.py/ nocase ascii wide
                        $string2_Browser_password_stealer_offensive_tool_keyword = /\/chromium_based_browsers\.py/ nocase ascii wide
                        $string3_Browser_password_stealer_offensive_tool_keyword = /\\chromium_based_browsers\.py/ nocase ascii wide
                        $string4_Browser_password_stealer_offensive_tool_keyword = /Browser\-password\-stealer\.git/ nocase ascii wide
                        $string5_Browser_password_stealer_offensive_tool_keyword = "Browser-password-stealer-master" nocase ascii wide
                        $string6_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\/cookies\.txt/ nocase ascii wide
                        $string7_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\/credit_cards\.txt/ nocase ascii wide
                        $string8_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\/history\.txt/ nocase ascii wide
                        $string9_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\/login_data\.txt/ nocase ascii wide
                        $string10_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\\cookies\.txt/ nocase ascii wide
                        $string11_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\\credit_cards\.txt/ nocase ascii wide
                        $string12_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\\history\.txt/ nocase ascii wide
                        $string13_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\\login_data\.txt/ nocase ascii wide
                        $string14_Browser_password_stealer_offensive_tool_keyword = "henry-richard7/Browser-password-stealer" nocase ascii wide
                        $string15_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\/cookies\.txt/ nocase ascii wide
                        $string16_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\/credit_cards\.txt/ nocase ascii wide
                        $string17_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\/history\.txt/ nocase ascii wide
                        $string18_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\/login_data\.txt/ nocase ascii wide
                        $string19_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\\cookies\.txt/ nocase ascii wide
                        $string20_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\\credit_cards\.txt/ nocase ascii wide
                        $string21_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\\history\.txt/ nocase ascii wide
                        $string22_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\\login_data\.txt/ nocase ascii wide
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