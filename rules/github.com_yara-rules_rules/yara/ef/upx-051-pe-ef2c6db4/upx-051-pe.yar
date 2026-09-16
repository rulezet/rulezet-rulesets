import "pe"
rule UPX_051_PE: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 D8 01 00 00 83 CD FF 31 DB 90 90 90 90 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90 90 90 B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF 75 }
    condition:
        $a at pe.entry_point

}