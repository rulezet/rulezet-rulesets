import "pe"
rule UPX_v0761_dos_exe_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8C C8 05 ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC }
    condition:
        $a at pe.entry_point

}