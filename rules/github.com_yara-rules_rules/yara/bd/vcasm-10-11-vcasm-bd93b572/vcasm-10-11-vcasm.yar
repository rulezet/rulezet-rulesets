import "pe"
rule vcasm_10_11_vcasm: PEiD
{
    strings:
        $a = { EB 01 9A 60 }
    condition:
        $a at pe.entry_point

}