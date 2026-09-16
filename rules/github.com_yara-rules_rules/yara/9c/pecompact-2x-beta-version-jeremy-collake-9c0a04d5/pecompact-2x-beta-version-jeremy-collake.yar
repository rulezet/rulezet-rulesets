import "pe"
rule PECompact_2x_beta_version_Jeremy_Collake: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? 00 80 00 28 40 }
    condition:
        $a at pe.entry_point

}