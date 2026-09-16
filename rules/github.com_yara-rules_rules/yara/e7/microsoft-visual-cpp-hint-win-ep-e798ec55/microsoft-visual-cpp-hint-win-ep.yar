import "pe"
rule Microsoft_Visual_Cpp_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 83 ?? ?? 6A 00 FF 15 F8 10 0B B0 8D ?? ?? ?? 51 6A 08 6A 00 6A 00 68 }
    condition:
        $a at pe.entry_point

}