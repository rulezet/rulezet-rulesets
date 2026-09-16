rule rule_KeyCredentialLink_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KeyCredentialLink' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeyCredentialLink"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KeyCredentialLink_offensive_tool_keyword = /\s\/domain\:.{0,100}\s\/dc\:.{0,100}\s\/getcredentials\s\/nowrap/ nocase ascii wide
                        $string2_KeyCredentialLink_offensive_tool_keyword = /\sKeyCredentialLink\.ps1/ nocase ascii wide
                        $string3_KeyCredentialLink_offensive_tool_keyword = /\.exe\sasktgt\s\/user\:.{0,100}\s\/certificate\:.{0,100}\s\/password\:/ nocase ascii wide
                        $string4_KeyCredentialLink_offensive_tool_keyword = /\/KeyCredentialLink\.git/ nocase ascii wide
                        $string5_KeyCredentialLink_offensive_tool_keyword = /\/KeyCredentialLink\.ps1/ nocase ascii wide
                        $string6_KeyCredentialLink_offensive_tool_keyword = /\\KeyCredentialLink\.ps1/ nocase ascii wide
                        $string7_KeyCredentialLink_offensive_tool_keyword = /\\Public\\Documents\\DSInternals/ nocase ascii wide
                        $string8_KeyCredentialLink_offensive_tool_keyword = "1257077a68f9725d863947e0931a44727fceaad6565b73b9f8d873cc3d028e00" nocase ascii wide
                        $string9_KeyCredentialLink_offensive_tool_keyword = "5db4c8112942c658a4f14d16fff13781dd705273c0050b2ada09ec79c7cb7c87" nocase ascii wide
                        $string10_KeyCredentialLink_offensive_tool_keyword = "Add-KeyCredentials -target " nocase ascii wide
                        $string11_KeyCredentialLink_offensive_tool_keyword = "AERTSW50ZXJuYWxzXHg4Nlx2Y3J1bnRpbWUxNDBfdGhyZWFkcy5kbGxQSwECFAAUAAAACAAnnY1YrbP4grERAAA9RQAADwAAAAAAAAAAAAAAAABk7yEARFNJbnRlcm5hbHMuY2F0UEsFBgAAAAAwADAAdRAAAEIBIgAAAA==" nocase ascii wide
                        $string12_KeyCredentialLink_offensive_tool_keyword = "Clear-KeyCredentials -target " nocase ascii wide
                        $string13_KeyCredentialLink_offensive_tool_keyword = "Leo4j/KeyCredentialLink" nocase ascii wide
                        $string14_KeyCredentialLink_offensive_tool_keyword = "List-KeyCredentials -target " nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}