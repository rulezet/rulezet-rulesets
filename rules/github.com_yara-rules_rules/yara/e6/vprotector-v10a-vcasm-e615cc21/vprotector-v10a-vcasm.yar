import "pe"
rule VProtector_V10A_vcasm: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 8A 8E 40 00 68 C6 8E 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }
    condition:
        $a at pe.entry_point

}