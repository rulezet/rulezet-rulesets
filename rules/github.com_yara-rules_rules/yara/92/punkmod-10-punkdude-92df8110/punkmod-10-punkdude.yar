import "pe"
rule PuNkMoD_10_PuNkDuDe: PEiD
{
    strings:
        $a = { 94 B9 60 01 00 00 BC ?? ?? 40 00 80 34 0C ?? E2 FA EB DF }
    condition:
        $a at pe.entry_point

}