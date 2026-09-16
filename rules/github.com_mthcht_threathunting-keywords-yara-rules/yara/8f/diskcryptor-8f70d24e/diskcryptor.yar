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
                        $string15 = /dcrypt_setup_.{0,1000}\.exe/ nocase ascii wide
                        $string16 = /dcrypt_winpe\.zip/ nocase ascii wide
                        $string17 = "DiskCryptor Device Installation Disk" nocase ascii wide
                        $string18 = "DiskCryptor driver" nocase ascii wide
                        $string19 = "DISKCRYPTOR_MUTEX" nocase ascii wide
                        $string20 = "DiskCryptor-master" nocase ascii wide
                        $string21 = /Public\\dcinst\.exe/ nocase ascii wide
                        $string22 = /SYSTEM\\CurrentControlSet\\Services\\dcrypt/ nocase ascii wide

    condition:
        any of them
}