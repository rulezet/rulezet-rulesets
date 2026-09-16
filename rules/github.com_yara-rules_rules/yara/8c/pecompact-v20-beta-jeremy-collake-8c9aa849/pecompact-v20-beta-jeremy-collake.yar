import "pe"
rule PECompact_v20_beta_Jeremy_Collake: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }
    condition:
        $a at pe.entry_point

}