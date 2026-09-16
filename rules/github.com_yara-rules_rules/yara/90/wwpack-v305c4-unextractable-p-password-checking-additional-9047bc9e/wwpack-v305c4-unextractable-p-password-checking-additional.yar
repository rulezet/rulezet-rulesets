import "pe"
rule WWPACK_v305c4_Unextractable_p_Password_checking_additional: PEiD
{
    strings:
        $a = { 03 05 80 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
    condition:
        $a at pe.entry_point

}