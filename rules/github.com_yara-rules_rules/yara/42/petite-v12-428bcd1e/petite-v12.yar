import "pe"
rule PEtite_v12: PEiD
{
    strings:
        $a = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }
    condition:
        $a at pe.entry_point

}