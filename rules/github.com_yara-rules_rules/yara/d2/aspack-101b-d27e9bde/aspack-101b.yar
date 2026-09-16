import "pe"
rule ASPack_101b: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED D2 2A 44 00 B8 CC 2A 44 00 03 C5 2B 85 A5 2E 44 00 89 85 B1 2E 44 00 80 BD 9C 2E 44 00 00 75 15 FE 85 9C 2E 44 00 E8 1D 00 00 00 E8 E4 01 00 00 E8 7A 02 00 00 8B 85 9D 2E 44 00 03 85 B1 2E 44 00 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}