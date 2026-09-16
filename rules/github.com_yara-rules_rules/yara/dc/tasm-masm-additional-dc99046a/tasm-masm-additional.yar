import "pe"
rule TASM_MASM_additional: PEiD
{
    strings:
        $a = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 }
    condition:
        $a at pe.entry_point

}