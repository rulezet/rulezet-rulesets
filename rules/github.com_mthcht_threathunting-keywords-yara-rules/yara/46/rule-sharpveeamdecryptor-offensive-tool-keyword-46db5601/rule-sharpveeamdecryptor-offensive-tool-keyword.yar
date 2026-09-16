rule rule_SharpVeeamDecryptor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpVeeamDecryptor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpVeeamDecryptor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpVeeamDecryptor_offensive_tool_keyword = "\"VeeamBackupCreds\"" nocase ascii wide
                        $string2_SharpVeeamDecryptor_offensive_tool_keyword = /\/SharpVeeamDecryptor\./ nocase ascii wide
                        $string3_SharpVeeamDecryptor_offensive_tool_keyword = /\\SharpVeeamDecryptor\-/ nocase ascii wide
                        $string4_SharpVeeamDecryptor_offensive_tool_keyword = /\\SharpVeeamDecryptor\./ nocase ascii wide
                        $string5_SharpVeeamDecryptor_offensive_tool_keyword = ">VeeamBackupCreds<" nocase ascii wide
                        $string6_SharpVeeamDecryptor_offensive_tool_keyword = "267c2cc1712018393f79e00ee869f86e8be7522569e18ec76ab2c8deb36ba9d1" nocase ascii wide
                        $string7_SharpVeeamDecryptor_offensive_tool_keyword = "a0b465738c8244eae2e5b1c2574e621b044405cf9c3a574e44737ff08f9ea442" nocase ascii wide
                        $string8_SharpVeeamDecryptor_offensive_tool_keyword = "Author: @ShitSecure" nocase ascii wide
                        $string9_SharpVeeamDecryptor_offensive_tool_keyword = "d5fb8f91ffff93aecf6c68f864ce853a541d0bb7b53db3f5eb2fd6b8310cc5f2" nocase ascii wide
                        $string10_SharpVeeamDecryptor_offensive_tool_keyword = "EE728741-4BD4-4F7C-8E41-B8328706EA84" nocase ascii wide
                        $string11_SharpVeeamDecryptor_offensive_tool_keyword = "f2514c44ea0566d15601e6179fab45dbb023b78cb0903a28196a31599f17be00" nocase ascii wide
                        $string12_SharpVeeamDecryptor_offensive_tool_keyword = /GetRegistryValue.{0,100}SOFTWARE\\Veeam\\Veeam\sBackup\sCatalog/ nocase ascii wide
                        $string13_SharpVeeamDecryptor_offensive_tool_keyword = "S3cur3Th1sSh1t/SharpVeeamDecryptor" nocase ascii wide
                        $string14_SharpVeeamDecryptor_offensive_tool_keyword = /SELECT\suser_name\,\spassword\sFROM\sVeeamBackup\.dbo\.Credentials/ nocase ascii wide
                        $string15_SharpVeeamDecryptor_offensive_tool_keyword = /SharpVeeamDecryptor\.exe/ nocase ascii wide
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