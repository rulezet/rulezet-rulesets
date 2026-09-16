import "pe"
rule R_Crypt_091: PEiD
{
    strings:
        $a = { 68 00 01 60 BF 03 01 B9 00 00 B0 00 2E 30 05 FE C0 47 E2 F8 61 C7 06 00 01 00 00 C6 06 02 01 00 C3 }
    condition:
        $a at pe.entry_point

}