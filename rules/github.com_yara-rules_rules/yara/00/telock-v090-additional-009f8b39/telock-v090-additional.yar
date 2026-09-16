import "pe"
rule tElock_v090_additional: PEiD
{
    strings:
        $a = { E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }
    condition:
        $a at pe.entry_point

}