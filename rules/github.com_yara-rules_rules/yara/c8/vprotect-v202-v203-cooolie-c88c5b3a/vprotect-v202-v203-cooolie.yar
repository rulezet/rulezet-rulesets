import "pe"
rule Vprotect_V202_V203_CoooLie: PEiD
{
    strings:
        $a = { 66 F7 D7 66 50 66 58 66 F7 D7 9C 9D 8B 67 28 57 66 8B DB 5F 61 8D AD F4 FF FF FF 8D AD 0C 00 00 00 66 57 66 5F 8B FF 9D 9C 8D 80 F0 FF FF FF 8D 80 10 00 00 00 9D 66 F7 D2 66 F7 D2 }
    condition:
        $a at pe.entry_point

}