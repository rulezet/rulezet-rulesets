import "pe"
rule Upack_v037_v038_Beta_Strip_base_relocation_table_Option_Dwing: PEiD
{
    strings:
        $a = { 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 }
    condition:
        $a at pe.entry_point

}