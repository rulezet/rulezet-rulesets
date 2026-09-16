import "pe"
rule PCrypt_350_COM: PEiD
{
    strings:
        $a = { 50 43 52 59 50 54 E9 }
    condition:
        $a at pe.entry_point

}