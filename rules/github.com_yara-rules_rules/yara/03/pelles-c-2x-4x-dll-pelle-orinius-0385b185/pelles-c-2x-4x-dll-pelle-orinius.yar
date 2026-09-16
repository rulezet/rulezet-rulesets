import "pe"
rule Pelles_C_2x_4x_DLL_Pelle_Orinius: PEiD
{
    strings:
        $a = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 }
    condition:
        $a at pe.entry_point

}