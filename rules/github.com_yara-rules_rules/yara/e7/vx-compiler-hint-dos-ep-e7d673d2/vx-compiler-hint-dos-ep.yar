import "pe"
rule Vx_Compiler_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E }
    condition:
        $a at pe.entry_point

}