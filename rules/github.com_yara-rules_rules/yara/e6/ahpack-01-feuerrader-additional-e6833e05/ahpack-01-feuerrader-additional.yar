import "pe"
rule AHPack_01_FEUERRADER_additional: PEiD
{
    strings:
        $a = { 60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }
    condition:
        $a at pe.entry_point

}