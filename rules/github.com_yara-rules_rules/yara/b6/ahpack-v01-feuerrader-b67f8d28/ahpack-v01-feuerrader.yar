import "pe"
rule AHPack_V01_FEUERRADER: PEiD
{
    strings:
        $a = { 60 68 54 ?? ?? 00 B8 48 ?? ?? 00 FF 10 68 B3 ?? ?? 00 50 B8 44 ?? ?? 00 FF 10 68 00 }
    condition:
        $a at pe.entry_point

}