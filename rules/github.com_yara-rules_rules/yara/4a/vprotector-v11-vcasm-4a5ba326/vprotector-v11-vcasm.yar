import "pe"
rule VProtector_V11_vcasm: PEiD
{
    strings:
        $a = { B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00 }
    condition:
        $a at pe.entry_point

}