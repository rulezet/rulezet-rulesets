import "pe"
rule Crinkler_V01_V02_Rune_LHStubbe_and_Aske_Simon_Christensen: PEiD
{
    strings:
        $a = { B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9 }
    condition:
        $a at pe.entry_point

}