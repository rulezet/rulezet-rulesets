import "pe"
rule eXpressor_v10_CGSoftLabs_additional: PEiD
{
    strings:
        $a = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 }
    condition:
        $a at pe.entry_point

}