import "pe"
rule _PseudoSigner_02_LCC_Win32_1x_Anorganix: PEiD
{
    strings:
        $a = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 }
    condition:
        $a at pe.entry_point

}