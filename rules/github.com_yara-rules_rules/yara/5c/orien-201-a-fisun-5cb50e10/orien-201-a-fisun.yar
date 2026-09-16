import "pe"
rule ORiEN_201_A_Fisun: PEiD
{
    strings:
        $a = { E9 5D 01 00 00 }
    condition:
        $a at pe.entry_point

}