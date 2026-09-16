import "pe"
rule Go32Stub_v200_DOS_Extender_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 80 }
    condition:
        $a at pe.entry_point

}