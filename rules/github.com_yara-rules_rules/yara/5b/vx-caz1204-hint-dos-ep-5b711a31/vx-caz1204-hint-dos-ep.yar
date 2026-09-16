import "pe"
rule Vx_Caz1204_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10 }
    condition:
        $a at pe.entry_point

}