import "pe"
rule PE_Crypt_102: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 }
    condition:
        $a at pe.entry_point

}