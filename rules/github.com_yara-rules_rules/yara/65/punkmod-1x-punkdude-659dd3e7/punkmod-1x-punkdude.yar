import "pe"
rule PuNkMoD_1x_PuNkDuDe: PEiD
{
    strings:
        $a = { 94 B9 ?? ?? 00 00 BC ?? ?? ?? ?? 80 34 0C }
    condition:
        $a at pe.entry_point

}