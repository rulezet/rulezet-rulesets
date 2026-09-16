import "pe"
rule Spirit_15: PEiD
{
    strings:
        $a = { E9 00 00 5B 24 55 50 44 FB 32 2E 31 5D }
    condition:
        $a at pe.entry_point

}