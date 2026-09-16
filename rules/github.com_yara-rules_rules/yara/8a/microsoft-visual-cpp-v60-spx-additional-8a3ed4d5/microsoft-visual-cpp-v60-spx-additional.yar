import "pe"
rule Microsoft_Visual_Cpp_v60_SPx_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15 }
    condition:
        $a at pe.entry_point

}