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
                        $string15_DiskCryptor_offensive_tool_keyword = /dcrypt_setup_.{0,1000}\.exe/ nocase ascii wide
                        $string16_DiskCryptor_offensive_tool_keyword = /dcrypt_winpe\.zip/ nocase ascii wide
                        $string17_DiskCryptor_offensive_tool_keyword = "DiskCryptor Device Installation Disk" nocase ascii wide
                        $string18_DiskCryptor_offensive_tool_keyword = "DiskCryptor driver" nocase ascii wide
                        $string19_DiskCryptor_offensive_tool_keyword = "DISKCRYPTOR_MUTEX" nocase ascii wide
                        $string20_DiskCryptor_offensive_tool_keyword = "DiskCryptor-master" nocase ascii wide
                        $string21_DiskCryptor_offensive_tool_keyword = /Public\\dcinst\.exe/ nocase ascii wide
                        $string22_DiskCryptor_offensive_tool_keyword = /SYSTEM\\CurrentControlSet\\Services\\dcrypt/ nocase ascii wide

    condition:
        any of them
}