import "pe"
rule WWPACK_v302_v302a_Extractable: PEiD
{
    strings:
        $a = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 33 C9 B1 ?? 51 06 06 BB ?? ?? 53 8C D3 }
    condition:
        $a at pe.entry_point

}