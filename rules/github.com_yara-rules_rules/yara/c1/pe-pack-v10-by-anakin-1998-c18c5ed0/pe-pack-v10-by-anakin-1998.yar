import "pe"
rule PE_PACK_v10_by_ANAKiN_1998_: PEiD
{
    strings:
        $a = { 74 ?? E9 ?? ?? ?? ?? 00 00 00 00 }
    condition:
        $a at pe.entry_point

}