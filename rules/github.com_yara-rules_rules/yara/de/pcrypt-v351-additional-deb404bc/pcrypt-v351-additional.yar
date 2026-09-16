import "pe"
rule PCrypt_v351_additional: PEiD
{
    strings:
        $a = { 50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9 }
    condition:
        $a at pe.entry_point

}