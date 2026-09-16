import "pe"
rule Microsoft_CAB_SFX: PEiD
{
    strings:
        $a = { E8 0A 00 00 00 E9 7A FF FF FF CC CC CC CC CC }
    condition:
        $a at pe.entry_point

}