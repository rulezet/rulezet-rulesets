import "pe"
rule pirit_v15_additional: PEiD
{
    strings:
        $a = { 5B 24 55 50 44 FB 32 2E 31 5D }
    condition:
        $a at pe.entry_point

}