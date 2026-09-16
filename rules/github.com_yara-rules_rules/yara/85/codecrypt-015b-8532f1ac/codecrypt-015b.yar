import "pe"
rule CodeCrypt_015b: PEiD
{
    strings:
        $a = { EB 02 0F 4D 55 EB 02 0F C7 E8 00 00 00 00 EB 02 83 3D 5D EB 03 0F CA 0F 81 ED 70 23 40 00 52 8B 54 24 08 E8 A2 FD FF FF 89 95 D0 2A 40 00 5A EB 02 0F 4D EB 02 FF 1D EB 02 0F C7 EB 02 0F C0 EB 03 0F CA 0F EB 03 FF 1D 34 EB 02 83 3D EB 02 C7 }
    condition:
        $a at pe.entry_point

}