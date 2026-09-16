import "pe"
rule tElock_v071b7_additional: PEiD
{
    strings:
        $a = { 60 E8 48 11 00 00 C3 83 }
    condition:
        $a at pe.entry_point

}