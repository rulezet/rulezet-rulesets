rule rule_DiskCryptor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DiskCryptor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DiskCryptor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DiskCryptor_offensive_tool_keyword = /\/dcrypt\.exe/ nocase ascii wide
                        $string2_DiskCryptor_offensive_tool_keyword = /\/dcrypt_setup\.exe/ nocase ascii wide
                        $string3_DiskCryptor_offensive_tool_keyword = /\/DiskCryptor\.git/ nocase ascii wide
                        $string4_DiskCryptor_offensive_tool_keyword = /\\dcrypt\.exe/ nocase ascii wide
                        $string5_DiskCryptor_offensive_tool_keyword = /\\dcrypt\.sys/ nocase ascii wide
                        $string6_DiskCryptor_offensive_tool_keyword = /\\DCrypt\\Bin/ nocase ascii wide
                        $string7_DiskCryptor_offensive_tool_keyword = /\\dcrypt_setup\.exe/ nocase ascii wide
                        $string8_DiskCryptor_offensive_tool_keyword = /\\Public\\dcapi\.dll/ nocase ascii wide
                        $string9_DiskCryptor_offensive_tool_keyword = "A38C04C7-B172-4897-8471-E3478903035E" nocase ascii wide
                        $string10_DiskCryptor_offensive_tool_keyword = "A38C04C7-B172-4897-8471-E3478903035E" nocase ascii wide
                        $string11_DiskCryptor_offensive_tool_keyword = "DavidXanatos/DiskCryptor" nocase ascii wide
                        $string12_DiskCryptor_offensive_tool_keyword = /dccon\.exe\s\-encrypt2/ nocase ascii wide
                        $string13_DiskCryptor_offensive_tool_keyword = /dcrypt_bartpe\.zip/ nocase ascii wide
                        $string14_DiskCryptor_offensive_tool_keyword = /dcrypt_install\.iss/ nocase ascii wide
                        $string15_DiskCryptor_offensive_tool_keyword = /dcrypt_setup_.{0,100}\.exe/ nocase ascii wide
                        $string16_DiskCryptor_offensive_tool_keyword = /dcrypt_winpe\.zip/ nocase ascii wide
                        $string17_DiskCryptor_offensive_tool_keyword = "DiskCryptor Device Installation Disk" nocase ascii wide
                        $string18_DiskCryptor_offensive_tool_keyword = "DiskCryptor driver" nocase ascii wide
                        $string19_DiskCryptor_offensive_tool_keyword = "DISKCRYPTOR_MUTEX" nocase ascii wide
                        $string20_DiskCryptor_offensive_tool_keyword = "DiskCryptor-master" nocase ascii wide
                        $string21_DiskCryptor_offensive_tool_keyword = /Public\\dcinst\.exe/ nocase ascii wide
                        $string22_DiskCryptor_offensive_tool_keyword = /SYSTEM\\CurrentControlSet\\Services\\dcrypt/ nocase ascii wide
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