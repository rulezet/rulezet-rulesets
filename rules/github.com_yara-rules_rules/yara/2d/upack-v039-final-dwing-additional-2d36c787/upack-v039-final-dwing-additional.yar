import "pe"
rule Upack_v039_final_Dwing_additional: PEiD
{
    strings:
        $a = { 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 }
    condition:
        $a at pe.entry_point

}