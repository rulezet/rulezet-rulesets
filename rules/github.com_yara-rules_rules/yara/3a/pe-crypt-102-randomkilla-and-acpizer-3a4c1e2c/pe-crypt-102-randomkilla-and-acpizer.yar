import "pe"
rule PE_Crypt_102_randomkilla_and_acpizer: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 }
    condition:
        $a at pe.entry_point

}