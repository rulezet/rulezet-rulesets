import "pe"
rule PEX_v099_bart: PEiD
{
    strings:
        $a = { 68 FA 30 41 00 C3 20 20 }
    condition:
        $a at pe.entry_point

}