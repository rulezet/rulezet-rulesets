import "pe"
rule PE_Protector_V260hyings_PE_Armor_V0460_modify_Engprog: PEiD
{
    strings:
        $a = { 55 53 51 52 56 57 E8 E1 00 00 00 }
    condition:
        $a at pe.entry_point

}