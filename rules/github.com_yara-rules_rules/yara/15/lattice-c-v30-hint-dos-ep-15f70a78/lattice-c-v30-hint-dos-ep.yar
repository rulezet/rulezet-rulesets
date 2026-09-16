import "pe"
rule Lattice_C_v30_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA B8 ?? ?? 8E D8 B8 ?? ?? 8E }
    condition:
        $a at pe.entry_point

}