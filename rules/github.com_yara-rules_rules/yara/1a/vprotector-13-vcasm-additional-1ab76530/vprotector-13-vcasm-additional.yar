import "pe"
rule vprotector_13_vcasm_additional: PEiD
{
    strings:
        $a = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 }
    condition:
        $a at pe.entry_point

}