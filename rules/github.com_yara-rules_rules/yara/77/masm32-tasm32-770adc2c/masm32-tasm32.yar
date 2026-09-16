import "pe"
rule MASM32_TASM32: PEiD
{
    strings:
        $a = { 2B C0 50 E8 }
    condition:
        $a at pe.entry_point

}