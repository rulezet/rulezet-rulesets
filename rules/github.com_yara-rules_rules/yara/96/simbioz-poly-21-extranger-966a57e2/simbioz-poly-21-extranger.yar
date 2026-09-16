import "pe"
rule SimbiOZ_Poly_21_Extranger: PEiD
{
    strings:
        $a = { 55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90 }
    condition:
        $a at pe.entry_point

}