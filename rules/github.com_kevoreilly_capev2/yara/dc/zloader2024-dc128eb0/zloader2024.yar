rule Zloader2024
{
    meta:
        author = "enzok"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
        hash = "49405370a33abbf131c5d550cebe00780cc3fd3cbe888220686582ae88f16af7"
    strings:
        $conf_1 = {48 01 ?? 48 8D 15 [4] 41 B8 ?? 04 00 00 E8 [4] [0-5] C7 [1-2] 00 00 00 00}
        $confkey_1 = {48 8D 15 [4] 48 89 ?? 49 89 ?? E8 [4] [0-5] C7 [1-2] 00 00 00 00}
        $confkey_2 = {48 01 ?? 48 8D 15 [4] 41 B8 10 00 00 00 E8 [4] [0-5] C7 [1-2] 00 00 00 00 (48 8B|8B)}
        $confkey_3 = {48 01 ?? 48 8D 15 [4] 41 B8 10 00 00 00 E8 [4] [0-5] C7 [1-2] 00 00 00 00 48 83 C4}
    condition:
        uint16(0) == 0x5A4D and $conf_1 and 2 of ($confkey_*)
}