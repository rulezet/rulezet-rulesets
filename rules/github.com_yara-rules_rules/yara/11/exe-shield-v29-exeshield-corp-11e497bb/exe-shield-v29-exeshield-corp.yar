import "pe"
rule EXE_Shield_v29_Exeshield_Corp: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC }
    condition:
        $a at pe.entry_point

}