import "pe"
rule PE_Crypter: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D EB 26 }
    condition:
        $a at pe.entry_point

}