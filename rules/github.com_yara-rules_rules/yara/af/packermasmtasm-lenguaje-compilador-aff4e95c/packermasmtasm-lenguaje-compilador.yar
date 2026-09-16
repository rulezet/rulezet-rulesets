import "pe"
rule PackerMASMTASM_Lenguaje_Compilador: PEiD
{
    strings:
        $a = { 6A 00 E8 ?? ?? 00 00 A3 ?? 32 40 00 E8 ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}