import "pe"
rule TPPpack_clane: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 ?? E8 }
    condition:
        $a at pe.entry_point

}