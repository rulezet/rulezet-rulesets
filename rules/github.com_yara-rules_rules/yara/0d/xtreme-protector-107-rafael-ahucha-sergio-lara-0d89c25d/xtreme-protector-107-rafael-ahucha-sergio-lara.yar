import "pe"
rule Xtreme_Protector_107_Rafael_Ahucha_Sergio_Lara: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? 00 B9 8E ?? ?? 00 50 51 E8 1E 00 00 00 E8 00 00 00 00 58 2D 16 00 00 00 B9 }
    condition:
        $a at pe.entry_point

}