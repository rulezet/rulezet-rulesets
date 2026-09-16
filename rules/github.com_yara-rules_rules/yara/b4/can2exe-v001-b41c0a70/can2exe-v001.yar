import "pe"
rule CAN2EXE_v001: PEiD
{
    strings:
        $a = { 26 8E 06 ?? ?? B9 ?? ?? 33 C0 8B F8 F2 AE E3 ?? 26 38 05 75 ?? EB ?? E9 }
    condition:
        $a at pe.entry_point

}