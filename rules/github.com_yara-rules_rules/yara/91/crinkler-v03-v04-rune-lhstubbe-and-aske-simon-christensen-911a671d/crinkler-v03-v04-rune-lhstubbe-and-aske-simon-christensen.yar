import "pe"
rule Crinkler_V03_V04_Rune_LHStubbe_and_Aske_Simon_Christensen: PEiD
{
    strings:
        $a = { B8 00 00 42 00 31 DB 43 EB 58 }
    condition:
        $a at pe.entry_point

}