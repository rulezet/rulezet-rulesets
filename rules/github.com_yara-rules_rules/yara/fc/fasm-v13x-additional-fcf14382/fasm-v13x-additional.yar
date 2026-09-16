import "pe"
rule FASM_v13x_additional: PEiD
{
    strings:
        $a = { 6A ?? FF 15 ?? ?? ?? ?? A3 }
    condition:
        $a at pe.entry_point

}