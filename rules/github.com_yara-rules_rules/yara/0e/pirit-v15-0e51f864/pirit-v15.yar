import "pe"
rule PIRIT_v15: PEiD
{
    strings:
        $a = { B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21 }
    condition:
        $a at pe.entry_point

}