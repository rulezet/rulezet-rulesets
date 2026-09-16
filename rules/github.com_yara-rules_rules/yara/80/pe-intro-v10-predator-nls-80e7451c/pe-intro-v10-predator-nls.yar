import "pe"
rule PE_Intro_v10_Predator_NLS: PEiD
{
    strings:
        $a = { 8B 04 24 9C 60 E8 00 00 00 00 5D 81 ED 0A 45 40 00 80 BD 67 44 40 00 00 0F 85 48 }
    condition:
        $a at pe.entry_point

}