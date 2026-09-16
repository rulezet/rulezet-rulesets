import "pe"
rule PEtite_v12_Ian_Luck: PEiD
{
    strings:
        $a = { 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 }
    condition:
        $a at pe.entry_point

}