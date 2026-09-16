import "pe"
rule Inno_Setup_Module_v5: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? F3 FF FF E8 ?? F4 FF FF 33 C0 55 }
    condition:
        $a at pe.entry_point

}