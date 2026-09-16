import "pe"
rule tElock_v071b2_additional: PEiD
{
    strings:
        $a = { 60 E8 44 11 00 00 C3 83 }
    condition:
        $a at pe.entry_point

}