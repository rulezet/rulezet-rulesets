import "pe"
rule SDW_v174_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? 54 5B 3B DC 75 ?? EB ?? 9C 5B 81 ?? ?? ?? 53 9D 9C 58 }
    condition:
        $a at pe.entry_point

}