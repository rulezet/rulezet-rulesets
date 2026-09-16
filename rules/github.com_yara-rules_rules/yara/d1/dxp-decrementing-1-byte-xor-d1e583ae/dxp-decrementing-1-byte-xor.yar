import "pe"
rule dxp_Decrementing_1_byte_XOR: PEiD
{
    strings:
        $a = { 30 10 FE CA 48 49 ?? 85 C9 75 F5 }
    condition:
        $a at pe.entry_point

}