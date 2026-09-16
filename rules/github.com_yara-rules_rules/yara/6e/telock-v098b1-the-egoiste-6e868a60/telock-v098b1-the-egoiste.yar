import "pe"
rule tElock_v098b1_tHE_EGOiSTE: PEiD
{
    strings:
        $a = { E9 25 E4 FF FF }
    condition:
        $a at pe.entry_point

}