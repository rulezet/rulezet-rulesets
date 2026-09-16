import "pe"
rule WWPack32_v1x_additional: PEiD
{
    strings:
        $a = { 53 55 8B E8 33 DB EB 60 }
    condition:
        $a at pe.entry_point

}