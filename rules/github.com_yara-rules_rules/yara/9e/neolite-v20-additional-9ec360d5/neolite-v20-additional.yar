import "pe"
rule Neolite_v20_additional: PEiD
{
    strings:
        $a = { E9 A6 00 00 00 }
    condition:
        $a at pe.entry_point

}