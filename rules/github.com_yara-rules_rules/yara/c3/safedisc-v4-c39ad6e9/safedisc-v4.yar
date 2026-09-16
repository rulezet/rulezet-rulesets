import "pe"
rule SafeDisc_v4: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F }
    condition:
        $a at pe.entry_point

}