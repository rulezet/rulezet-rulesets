import "pe"
rule PEtite_v14: PEiD
{
    strings:
        $a = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC }
    condition:
        $a at pe.entry_point

}