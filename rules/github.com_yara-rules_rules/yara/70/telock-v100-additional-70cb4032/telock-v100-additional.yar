import "pe"
rule tElock_v100_additional: PEiD
{
    strings:
        $a = { E9 E5 E2 FF FF }
    condition:
        $a at pe.entry_point

}