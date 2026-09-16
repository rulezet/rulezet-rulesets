import "pe"
rule WWPACK_v305c4_Extr_Passwcheck_Vir_shield_additional: PEiD
{
    strings:
        $a = { 03 05 C0 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
    condition:
        $a at pe.entry_point

}