rule PEiD_01743_Pohernah_Crypter_V1_0_2____Kas_
{
    meta:
        description = "[Pohernah Crypter V1.0.2 -> Kas]"
        ep_only = "true"
    strings:
        $a = {60 E8 00 00 00 00 5D 81 ED DE 26 40 00 8B BD 05 28 40 00 8B 8D 0D 28 40 00 B8 25 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 09 28 40 00 31 C0 51 31 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 09 28 40 00 8B 85 11}
    condition:
        $a
}