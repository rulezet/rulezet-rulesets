import "pe"
rule EXEPACK_v405_v406_additional: PEiD
{
    strings:
        $a = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 06 ?? ?? 8E C0 8B 0E ?? ?? 8B F9 4F 8B F7 FD F3 A4 }
    condition:
        $a at pe.entry_point

}