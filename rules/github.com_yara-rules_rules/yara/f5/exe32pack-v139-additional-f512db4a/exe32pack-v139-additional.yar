import "pe"
rule EXE32Pack_v139_additional: PEiD
{
    strings:
        $a = { 8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 2E ?? ?? D1 C8 4F 81 }
    condition:
        $a at pe.entry_point

}