import "pe"
rule FASM_15x: PEiD
{
    strings:
        $a = { 6A 00 FF 15 ?? ?? 40 00 A3 ?? ?? 40 00 }
    condition:
        $a at pe.entry_point

}