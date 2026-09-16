import "pe"
rule WinZip_32_bit_SFX_v6x_module: PEiD
{
    strings:
        $a = { FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 38 08 74 06 40 80 38 00 75 F6 80 38 00 74 01 40 33 C9 ?? ?? ?? ?? FF 15 }
    condition:
        $a at pe.entry_point

}