import "pe"
rule Ding_Boys_PE_lock_Phantasm_v15b3: PEiD
{
    strings:
        $a = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0 }
    condition:
        $a at pe.entry_point

}