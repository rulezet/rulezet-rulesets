import "pe"
rule SuckStop_v111: PEiD
{
    strings:
        $a = { EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B }
    condition:
        $a at pe.entry_point

}