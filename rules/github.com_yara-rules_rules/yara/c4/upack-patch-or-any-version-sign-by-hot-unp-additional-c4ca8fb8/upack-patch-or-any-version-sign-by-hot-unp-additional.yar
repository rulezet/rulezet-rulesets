import "pe"
rule Upack_Patch_or_any_Version_Sign_by_hot_UNP_additional: PEiD
{
    strings:
        $a = { 60 E8 09 00 00 00 17 CD 00 00 E9 06 02 }
    condition:
        $a at pe.entry_point

}