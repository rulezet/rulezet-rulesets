import "pe"
rule Gamehouse_Media_Protector_Version_Unknown_additional: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}