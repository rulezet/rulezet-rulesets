import "pe"
rule Dev_Cue_4992_Bloodshed_Software: PEiD
{
    strings:
        $a = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D }
    condition:
        $a at pe.entry_point

}