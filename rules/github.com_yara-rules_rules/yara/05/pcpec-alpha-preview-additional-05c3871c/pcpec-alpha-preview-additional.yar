import "pe"
rule PCPEC_alpha_preview_additional: PEiD
{
    strings:
        $a = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 00 }
    condition:
        $a at pe.entry_point

}