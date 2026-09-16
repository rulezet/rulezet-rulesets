import "pe"
rule Ding_Boys_PE_lock_Phantasm_v10_v11: PEiD
{
    strings:
        $a = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }
    condition:
        $a at pe.entry_point

}