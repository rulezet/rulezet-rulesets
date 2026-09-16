import "pe"
rule Loader_for_Dos_Extender_by_Doug_Hoffmann: PEiD
{
    strings:
        $a = { 0E 1F 8C C6 B4 4A 50 BB FF FF CD 21 73 C1 58 CD 21 72 BC 03 DE 8B EB B8 21 35 CD 21 06 53 56 B8 87 16 CD 2F 0B C0 75 C9 B8 00 16 CD 2F A8 7F 75 07 E8 51 00 66 C1 CD 10 B8 87 16 CD 2F 80 F9 03 0F 82 16 00 55 68 C0 00 66 5D 80 E3 01 74 9D 66 }
    condition:
        $a at pe.entry_point

}