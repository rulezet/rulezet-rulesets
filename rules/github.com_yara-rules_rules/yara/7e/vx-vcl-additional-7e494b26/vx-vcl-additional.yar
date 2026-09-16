import "pe"
rule Vx_VCL_additional: PEiD
{
    strings:
        $a = { 01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3 }
    condition:
        $a at pe.entry_point

}