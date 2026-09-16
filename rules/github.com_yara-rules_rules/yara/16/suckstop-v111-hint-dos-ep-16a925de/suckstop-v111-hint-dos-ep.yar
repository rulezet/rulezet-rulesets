import "pe"
rule SuckStop_v111_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B }
    condition:
        $a at pe.entry_point

}