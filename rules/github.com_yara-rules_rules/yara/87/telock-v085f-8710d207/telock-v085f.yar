import "pe"
rule tElock_v085f: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }
    condition:
        $a at pe.entry_point

}