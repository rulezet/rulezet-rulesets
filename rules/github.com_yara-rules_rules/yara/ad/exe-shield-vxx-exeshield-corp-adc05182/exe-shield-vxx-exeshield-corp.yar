import "pe"
rule EXE_Shield_vxx_Exeshield_Corp: PEiD
{
    strings:
        $a = { 65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00 }
    condition:
        $a at pe.entry_point

}