import "pe"
rule EXE_Shield_v27_Exeshield_Corp: PEiD
{
    strings:
        $a = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00 }
    condition:
        $a at pe.entry_point

}