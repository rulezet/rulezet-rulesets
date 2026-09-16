import "pe"
rule MASMTASM: PEiD
{
    strings:
        $a = { 6A 00 E8 ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}