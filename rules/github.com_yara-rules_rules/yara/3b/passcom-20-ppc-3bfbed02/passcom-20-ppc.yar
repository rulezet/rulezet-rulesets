import "pe"
rule PassCOM_20_PPC: PEiD
{
    strings:
        $a = { BE 00 00 B9 64 01 87 }
    condition:
        $a at pe.entry_point

}