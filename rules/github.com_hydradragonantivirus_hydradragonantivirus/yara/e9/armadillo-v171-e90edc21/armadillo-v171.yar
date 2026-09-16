import "pe"
rule Armadillo_v171: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }
    condition:
        $a at pe.entry_point

}