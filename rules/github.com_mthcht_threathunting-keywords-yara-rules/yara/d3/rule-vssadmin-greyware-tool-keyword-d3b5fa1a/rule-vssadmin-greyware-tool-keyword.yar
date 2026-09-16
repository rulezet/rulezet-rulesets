rule rule_vssadmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vssadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vssadmin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_vssadmin_greyware_tool_keyword = /\.exe\sdelete\sshadows/ nocase ascii wide
                        $string2_vssadmin_greyware_tool_keyword = "vssadmin create shadow /for=C:" nocase ascii wide
                        $string3_vssadmin_greyware_tool_keyword = /vssadmin\screate\sshadow\s\/for\=C\:.{0,100}\s\\Temp\\.{0,100}\.tmp/ nocase ascii wide
                        $string4_vssadmin_greyware_tool_keyword = "vssadmin delete shadows /all /quiet" nocase ascii wide
                        $string5_vssadmin_greyware_tool_keyword = "vssadmin delete shadows" nocase ascii wide
                        $string6_vssadmin_greyware_tool_keyword = "vssadmin list shadows" nocase ascii wide
                        $string7_vssadmin_greyware_tool_keyword = /vssadmin.{0,100}\sDelete\sShadows\s\/All\s\/Quiet/ nocase ascii wide
                        $string8_vssadmin_greyware_tool_keyword = /vssadmin.{0,100}resize\sshadowstorage\s\/for\=c\:\s\/on\=c\:\s\/maxsize\=1/ nocase ascii wide
                        $string9_vssadmin_greyware_tool_keyword = /vssadmin\.exe\sCreate\sShadow\s\/for\=/ nocase ascii wide
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