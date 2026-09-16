import "pe"
rule SimbiOZ_13_Extranger: PEiD
{
    strings:
        $a = { 57 57 8D 7C 24 04 50 B8 00 ?? ?? ?? AB 58 5F C3 }
    condition:
        $a at pe.entry_point

}