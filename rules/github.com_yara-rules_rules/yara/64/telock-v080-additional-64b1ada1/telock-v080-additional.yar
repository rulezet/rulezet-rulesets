import "pe"
rule tElock_v080_additional: PEiD
{
    strings:
        $a = { 60 E8 F9 11 00 00 C3 83 }
    condition:
        $a at pe.entry_point

}