import "pe"
rule Go32Stub_v200T_DOS_Extender_additional: PEiD
{
    strings:
        $a = { 0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 3C }
    condition:
        $a at pe.entry_point

}