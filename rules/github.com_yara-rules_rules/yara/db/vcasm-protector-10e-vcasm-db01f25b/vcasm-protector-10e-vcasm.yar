import "pe"
rule Vcasm_Protector_10e_vcasm: PEiD
{
    strings:
        $a = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D }
    condition:
        $a at pe.entry_point

}