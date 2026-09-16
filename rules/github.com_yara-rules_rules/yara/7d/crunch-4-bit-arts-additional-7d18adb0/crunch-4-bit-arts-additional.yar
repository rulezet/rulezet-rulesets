import "pe"
rule Crunch_4_Bit_Arts_additional: PEiD
{
    strings:
        $a = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}