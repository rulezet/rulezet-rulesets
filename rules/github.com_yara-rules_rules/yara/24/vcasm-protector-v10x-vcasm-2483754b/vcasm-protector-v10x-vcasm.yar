import "pe"
rule VcAsm_Protector_V10X_VcAsm: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }
    condition:
        $a at pe.entry_point

}