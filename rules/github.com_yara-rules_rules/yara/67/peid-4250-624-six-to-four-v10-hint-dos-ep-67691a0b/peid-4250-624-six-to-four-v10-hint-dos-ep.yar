import "pe"
rule PEiD_4250_624_Six_to_Four_v10_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 50 55 4C 50 83 ?? ?? FC BF ?? ?? BE ?? ?? B5 ?? 57 F3 A5 C3 33 ED }
    condition:
        $a at pe.entry_point

}