import "pe"
rule Crinkler_V01_V02_Rune_LHStubbe_and_Aske_Simon_Christensen_additional: PEiD
{
    strings:
        $a = { B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF }
    condition:
        $a at pe.entry_point

}