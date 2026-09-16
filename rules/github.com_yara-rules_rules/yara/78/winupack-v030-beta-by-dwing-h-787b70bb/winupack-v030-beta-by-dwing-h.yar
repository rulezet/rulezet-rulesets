import "pe"
rule WinUpack_v030_beta_By_Dwing_h: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 }
    condition:
        $a at pe.entry_point

}