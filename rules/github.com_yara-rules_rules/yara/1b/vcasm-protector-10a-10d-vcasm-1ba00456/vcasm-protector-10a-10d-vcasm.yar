import "pe"
rule Vcasm_Protector_10a_10d_vcasm: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }
    condition:
        $a at pe.entry_point

}