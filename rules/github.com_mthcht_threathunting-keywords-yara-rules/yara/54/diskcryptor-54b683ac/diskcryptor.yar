rule DiskCryptor
{
    meta:
        description = "Detection patterns for the tool 'DiskCryptor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DiskCryptor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/dcrypt\.exe/ nocase ascii wide
                        $string2 = /\/dcrypt_setup\.exe/ nocase ascii wide
                        $string3 = /\/DiskCryptor\.git/ nocase ascii wide
                        $string4 = /\\dcrypt\.exe/ nocase ascii wide
                        $string5 = /\\dcrypt\.sys/ nocase ascii wide
                        $string6 = /\\DCrypt\\Bin/ nocase ascii wide
                        $string7 = /\\dcrypt_setup\.exe/ nocase ascii wide
                        $string8 = /\\Public\\dcapi\.dll/ nocase ascii wide
                        $string9 = "A38C04C7-B172-4897-8471-E3478903035E" nocase ascii wide
                        $string10 = "A38C04C7-B172-4897-8471-E3478903035E" nocase ascii wide
                        $string11 = "DavidXanatos/DiskCryptor" nocase ascii wide
                        $string12 = /dccon\.exe\s\-encrypt2/ nocase ascii wide
                        $string13 = /dcrypt_bartpe\.zip/ nocase ascii wide
                        $string14 = /dcrypt_install\.iss/ nocase ascii wide
                        $string15 = /dcrypt_setup_.{0,100}\.exe/ nocase ascii wide
                        $string16 = /dcrypt_winpe\.zip/ nocase ascii wide
                        $string17 = "DiskCryptor Device Installation Disk" nocase ascii wide
                        $string18 = "DiskCryptor driver" nocase ascii wide
                        $string19 = "DISKCRYPTOR_MUTEX" nocase ascii wide
                        $string20 = "DiskCryptor-master" nocase ascii wide
                        $string21 = /Public\\dcinst\.exe/ nocase ascii wide
                        $string22 = /SYSTEM\\CurrentControlSet\\Services\\dcrypt/ nocase ascii wide
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