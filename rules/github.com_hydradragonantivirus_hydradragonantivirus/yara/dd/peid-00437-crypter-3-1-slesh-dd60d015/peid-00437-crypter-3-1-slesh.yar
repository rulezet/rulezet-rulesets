rule PEiD_00437_Crypter_3_1____SLESH_
{
    meta:
        description = "[Crypter 3.1 -> SLESH]"
        ep_only = "true"
    strings:
        $a = {68 FF 64 24 F0 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68}
    condition:
        $a
}