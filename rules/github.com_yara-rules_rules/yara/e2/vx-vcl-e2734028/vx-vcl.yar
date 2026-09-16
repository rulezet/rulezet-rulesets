import "pe"
rule Vx_VCL: PEiD
{
    strings:
        $a = { AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89 }
    condition:
        $a at pe.entry_point

}