import "pe"
rule tElock_v071_additional: PEiD
{
    strings:
        $a = { 60 E8 ED 10 00 00 C3 83 }
    condition:
        $a at pe.entry_point

}