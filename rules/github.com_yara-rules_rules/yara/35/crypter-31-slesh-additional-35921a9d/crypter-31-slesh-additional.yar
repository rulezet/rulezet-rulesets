import "pe"
rule Crypter_31_SLESH_additional: PEiD
{
    strings:
        $a = { 68 FF 64 24 F0 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 }
    condition:
        $a at pe.entry_point

}