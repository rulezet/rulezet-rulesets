import "pe"
rule PECompact_v2x: PEiD
{
    strings:
        $a = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 33 40 ?? ?? }
    condition:
        $a at pe.entry_point

}