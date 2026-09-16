import "pe"
rule Xtreme_Protector_100_105_Rafael_Ahucha_Sergio_Lara: PEiD
{
    strings:
        $a = { E9 ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}