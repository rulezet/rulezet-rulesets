import "pe"
rule Ding_Boys_PE_lock_Phantasm_v08: PEiD
{
    strings:
        $a = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }
    condition:
        $a at pe.entry_point

}