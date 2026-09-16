import "pe"
rule Escargot_V01_ppMeat: PEiD
{
    strings:
        $a = { EB 04 40 30 2E 31 60 68 61 }
    condition:
        $a at pe.entry_point

}