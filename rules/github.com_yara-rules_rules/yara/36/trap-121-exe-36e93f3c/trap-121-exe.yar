import "pe"
rule Trap_121_EXE: PEiD
{
    strings:
        $a = { E8 00 00 5B 83 C3 2B 90 8B D3 E8 01 00 01 5B 2E 80 3F 00 74 19 90 90 8B DA B9 94 04 EB 01 90 2E C0 07 00 2E 80 37 00 2E 80 2F 00 43 E2 F1 }
    condition:
        $a at pe.entry_point

}