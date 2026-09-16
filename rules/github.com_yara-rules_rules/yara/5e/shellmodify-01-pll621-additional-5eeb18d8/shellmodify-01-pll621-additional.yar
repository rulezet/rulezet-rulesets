import "pe"
rule ShellModify_01_pll621_additional: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00 }
    condition:
        $a at pe.entry_point

}