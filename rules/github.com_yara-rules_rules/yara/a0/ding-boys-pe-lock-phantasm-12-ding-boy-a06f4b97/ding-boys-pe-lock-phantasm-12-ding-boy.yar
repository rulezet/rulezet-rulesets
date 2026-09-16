import "pe"
rule Ding_Boys_PE_lock_Phantasm_12_Ding_Boy: PEiD
{
    strings:
        $a = { 55 57 56 52 51 53 9C FA 90 E8 00 00 00 00 5D 8B D5 }
    condition:
        $a at pe.entry_point

}