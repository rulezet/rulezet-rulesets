rule rule_whiskeysamlandfriends_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'whiskeysamlandfriends' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whiskeysamlandfriends"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_whiskeysamlandfriends_offensive_tool_keyword = /\s\-\-adfs\-host\s.{0,100}\s\-\-krb\-key\s.{0,100}\s\-\-krb\-ticket\s/ nocase ascii wide
                        $string2_whiskeysamlandfriends_offensive_tool_keyword = /\s\-\-target\-user\s.{0,100}\s\-\-dc\-ip\s.{0,100}\s\-command\s/ nocase ascii wide
                        $string3_whiskeysamlandfriends_offensive_tool_keyword = /\sticketsplease\./ nocase ascii wide
                        $string4_whiskeysamlandfriends_offensive_tool_keyword = "/shocknawe/" nocase ascii wide
                        $string5_whiskeysamlandfriends_offensive_tool_keyword = /\/ticketer\.py/ nocase ascii wide
                        $string6_whiskeysamlandfriends_offensive_tool_keyword = /\/ticketsplease\.py/ nocase ascii wide
                        $string7_whiskeysamlandfriends_offensive_tool_keyword = /ADFSpoof\.py/ nocase ascii wide
                        $string8_whiskeysamlandfriends_offensive_tool_keyword = /dcsync\.py/ nocase ascii wide
                        $string9_whiskeysamlandfriends_offensive_tool_keyword = "generate_golden_saml" nocase ascii wide
                        $string10_whiskeysamlandfriends_offensive_tool_keyword = "import DCSYNC" nocase ascii wide
                        $string11_whiskeysamlandfriends_offensive_tool_keyword = /shocknawe\.py/ nocase ascii wide
                        $string12_whiskeysamlandfriends_offensive_tool_keyword = /smb\.dcsync/ nocase ascii wide
                        $string13_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease adfs " nocase ascii wide
                        $string14_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease azure " nocase ascii wide
                        $string15_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease dcsync " nocase ascii wide
                        $string16_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease ldap " nocase ascii wide
                        $string17_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease saml " nocase ascii wide
                        $string18_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease ticket --domain" nocase ascii wide
                        $string19_whiskeysamlandfriends_offensive_tool_keyword = /ticketsplease\.modules\./ nocase ascii wide
                        $string20_whiskeysamlandfriends_offensive_tool_keyword = /whiskeysaml\.py/ nocase ascii wide
                        $string21_whiskeysamlandfriends_offensive_tool_keyword = "whiskeysamlandfriends" nocase ascii wide
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