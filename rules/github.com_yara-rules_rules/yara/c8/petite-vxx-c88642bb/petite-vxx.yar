import "pe"
rule PEtite_vxx: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 66 9C 60 50 }
    condition:
        $a at pe.entry_point

}