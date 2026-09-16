import "pe"
rule VX_TibsZhelatin_StormWorm_variant: PEiD
{
    strings:
        $a = { FF 74 24 1C 58 8D 80 ?? ?? 77 04 50 68 62 34 35 04 E8 }
    condition:
        $a at pe.entry_point

}