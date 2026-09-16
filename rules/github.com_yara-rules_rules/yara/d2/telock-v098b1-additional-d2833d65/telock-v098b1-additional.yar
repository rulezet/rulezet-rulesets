import "pe"
rule tElock_v098b1_additional: PEiD
{
    strings:
        $a = { E9 25 E4 FF FF }
    condition:
        $a at pe.entry_point

}