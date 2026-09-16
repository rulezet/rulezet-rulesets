import "pe"
rule Upack_v036_beta_Dwing: PEiD
{
    strings:
        $a = { BE E0 11 ?? ?? FF 36 E9 C3 00 00 00 48 01 ?? ?? 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C }
    condition:
        $a at pe.entry_point

}