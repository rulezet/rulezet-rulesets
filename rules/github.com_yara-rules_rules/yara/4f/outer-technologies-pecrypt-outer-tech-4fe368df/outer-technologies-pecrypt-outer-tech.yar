import "pe"
rule Outer_Technologies_PECrypt_Outer_Tech: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 9E 00 00 00 8D BD ?? ?? ?? ?? 8B F7 33 DB AD 33 C3 2D 2F 7B 38 13 C1 C0 10 35 3C 75 94 78 AB 43 E2 EC }
    condition:
        $a at pe.entry_point

}