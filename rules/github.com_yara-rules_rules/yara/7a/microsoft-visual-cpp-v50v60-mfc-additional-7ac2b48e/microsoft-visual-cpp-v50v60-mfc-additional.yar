import "pe"
rule Microsoft_Visual_Cpp_v50v60_MFC_additional: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 }
    condition:
        $a at pe.entry_point

}