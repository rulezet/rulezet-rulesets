import "pe"
rule tElock_v095_tHE_EGOiSTE: PEiD
{
    strings:
        $a = { E9 D5 E4 FF FF 00 }
    condition:
        $a at pe.entry_point

}