import "pe"
rule Upack_Patch_Dwing_additional: PEiD
{
    strings:
        $a = { 2A A3 F2 54 CE }
    condition:
        $a at pe.entry_point

}