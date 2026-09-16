import "pe"
rule PuNkMoD_11a_PuNkDuDe: PEiD
{
    strings:
        $a = { 94 B9 5E 01 00 00 BC ?? ?? ?? 00 80 34 0C ?? 80 2C 0C ?? D2 }
    condition:
        $a at pe.entry_point

}