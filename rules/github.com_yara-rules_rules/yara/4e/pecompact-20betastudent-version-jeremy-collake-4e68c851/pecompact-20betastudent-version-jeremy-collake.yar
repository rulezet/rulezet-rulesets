import "pe"
rule PECompact_20betastudent_version_Jeremy_Collake: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? EE 05 12 13 13 12 50 64 FF 35 00 00 00 00 64 89 25 00 }
    condition:
        $a at pe.entry_point

}