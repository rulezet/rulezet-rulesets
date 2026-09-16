import "pe"
rule SDProtector_V11x_Randy_Li: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 }
    condition:
        $a at pe.entry_point

}