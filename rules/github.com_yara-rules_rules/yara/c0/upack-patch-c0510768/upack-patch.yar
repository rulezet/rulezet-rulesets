import "pe"
rule Upack_Patch: PEiD
{
    strings:
        $a = { 81 3A 00 00 00 02 00 00 00 00 }
    condition:
        $a at pe.entry_point

}