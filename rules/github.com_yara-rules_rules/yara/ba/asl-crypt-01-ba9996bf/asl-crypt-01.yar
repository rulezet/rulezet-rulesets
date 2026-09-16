import "pe"
rule ASL_Crypt_01: PEiD
{
    strings:
        $a = { 41 2E 53 2E 4C F8 43 72 79 70 74 }
    condition:
        $a at pe.entry_point

}