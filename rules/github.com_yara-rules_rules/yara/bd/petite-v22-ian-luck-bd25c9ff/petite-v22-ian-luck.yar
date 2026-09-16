import "pe"
rule PEtite_v22_Ian_Luck: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 }
    condition:
        $a at pe.entry_point

}