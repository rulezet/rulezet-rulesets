import "pe"
rule PECompact_2x_Jeremy_Collake: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }
    condition:
        $a at pe.entry_point

}