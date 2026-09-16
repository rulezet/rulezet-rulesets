import "pe"
rule Unknown_Protected_Mode_compiler_2_additional: PEiD
{
    strings:
        $a = { FA FC 0E 1F E8 ?? ?? 8C C0 66 0F B7 C0 66 C1 E0 ?? 66 67 A3 }
    condition:
        $a at pe.entry_point

}