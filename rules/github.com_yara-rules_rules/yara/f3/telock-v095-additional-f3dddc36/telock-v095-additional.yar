import "pe"
rule tElock_v095_additional: PEiD
{
    strings:
        $a = { E9 D5 E4 FF FF 00 }
    condition:
        $a at pe.entry_point

}