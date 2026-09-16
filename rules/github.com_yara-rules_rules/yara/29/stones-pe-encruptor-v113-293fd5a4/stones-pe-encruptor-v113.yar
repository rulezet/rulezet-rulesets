import "pe"
rule Stones_PE_Encruptor_v113: PEiD
{
    strings:
        $a = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 }
    condition:
        $a at pe.entry_point

}