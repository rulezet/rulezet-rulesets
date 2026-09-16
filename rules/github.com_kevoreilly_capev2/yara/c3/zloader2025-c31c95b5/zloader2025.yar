rule Zloader2025
{
    meta:
        author = "enzok"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
        hash = "86ffd411b42d8d06bdb294f48e79393adeea586c56c5c75c1a68ce6315932881"
    strings:
        $conf = {4? 01 ?? [4] E8 [4] 4? 8D 15 [4] 4? 89 ?? 4? 89 ?? E8 [4] C7 46 30 00 00 00 00 8B 7E 34}
        $confkey_1 = {4? 01 ?? [2] E8 [4] 4? 8D 15 [4] 4? 89 ?? 4? 89 ?? E8 [4] C7 46 34 00 00 00 00 8B 46 38}
        $confkey_2 = {4? 01 ?? [2] E8 [4] 4? 8D 15 [4] 4? 89 ?? 4? 89 ?? E8 [4] C7 46 38 00 00 00 00 48 83 C4 28}
    condition:
        uint16(0) == 0x5A4D and $conf and all of ($confkey_*)
}