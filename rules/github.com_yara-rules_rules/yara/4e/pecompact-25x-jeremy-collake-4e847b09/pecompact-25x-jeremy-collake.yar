import "pe"
rule PECompact_25x_Jeremy_Collake: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? FF E0 }
    condition:
        $a at pe.entry_point

}