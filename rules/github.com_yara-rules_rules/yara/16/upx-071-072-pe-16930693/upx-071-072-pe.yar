import "pe"
rule UPX_071_072_PE: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA 00 00 FF 57 66 81 87 00 00 00 00 00 00 81 C6 B3 01 00 00 EB 0A 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 }
    condition:
        $a at pe.entry_point

}