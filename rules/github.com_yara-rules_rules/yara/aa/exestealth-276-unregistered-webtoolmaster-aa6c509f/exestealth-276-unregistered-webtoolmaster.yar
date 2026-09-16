import "pe"
rule EXEStealth_276_Unregistered_WebtoolMaster: PEiD
{
    strings:
        $a = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }
    condition:
        $a at pe.entry_point

}