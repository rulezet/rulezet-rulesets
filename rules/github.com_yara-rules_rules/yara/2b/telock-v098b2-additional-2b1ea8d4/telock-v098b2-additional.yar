import "pe"
rule tElock_v098b2_additional: PEiD
{
    strings:
        $a = { E9 1B E4 FF FF }
    condition:
        $a at pe.entry_point

}