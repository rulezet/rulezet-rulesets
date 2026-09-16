import "pe"
rule Upack_Unknown_DLL_Sign_by_hot_UNP: PEiD
{
    strings:
        $a = { 60 E8 09 00 00 00 17 CD 00 00 E9 06 02 }
    condition:
        $a at pe.entry_point

}