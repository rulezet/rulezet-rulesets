import "pe"
rule WinUpack_v030_beta_By_Dwing: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 }
        $b = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}