import "pe"
rule Petite_14_c1998_99_Ian_Luck_h_additional: PEiD
{
    strings:
        $a = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }
    condition:
        $a at pe.entry_point

}