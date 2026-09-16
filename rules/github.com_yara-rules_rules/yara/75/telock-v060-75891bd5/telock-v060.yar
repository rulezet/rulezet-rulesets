import "pe"
rule tElock_v060: PEiD
{
    strings:
        $a = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }
    condition:
        $a at pe.entry_point

}