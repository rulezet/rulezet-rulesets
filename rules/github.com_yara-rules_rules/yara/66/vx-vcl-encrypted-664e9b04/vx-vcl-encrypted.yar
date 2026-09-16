import "pe"
rule Vx_VCL_encrypted: PEiD
{
    strings:
        $a = { 01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3 }
    condition:
        $a at pe.entry_point

}