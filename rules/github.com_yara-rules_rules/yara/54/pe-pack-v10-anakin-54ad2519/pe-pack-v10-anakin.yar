import "pe"
rule PE_Pack_v10_ANAKiN: PEiD
{
    strings:
        $a = { 74 00 E9 ?? ?? ?? ?? 00 00 00 00 }
    condition:
        $a at pe.entry_point

}