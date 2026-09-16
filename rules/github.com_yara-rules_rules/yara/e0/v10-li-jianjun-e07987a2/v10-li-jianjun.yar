import "pe"
rule _v10_Li_Jianjun: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 }
    condition:
        $a at pe.entry_point

}