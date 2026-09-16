import "pe"
rule Vcasm_Protector_11_12_vcasm: PEiD
{
    strings:
        $a = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D }
    condition:
        $a at pe.entry_point

}