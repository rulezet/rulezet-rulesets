import "pe"
rule _SDProtector_11x_Randy_Li: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 }
    condition:
        $a at pe.entry_point

}