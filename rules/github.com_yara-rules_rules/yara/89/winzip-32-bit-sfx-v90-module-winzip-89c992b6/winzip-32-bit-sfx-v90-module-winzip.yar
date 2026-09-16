import "pe"
rule WinZip_32_bit_SFX_v90_module_Winzip: PEiD
{
    strings:
        $a = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A }
    condition:
        $a at pe.entry_point

}