import "pe"
rule ORiEN_V212_Fisun_AV: PEiD
{
    strings:
        $a = { E9 5D 01 00 00 CE D1 CE CD 0D }
    condition:
        $a at pe.entry_point

}