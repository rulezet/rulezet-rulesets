import "pe"
rule RLPack_119_Basic_Edition: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 ?? ?? 00 00 EB 0C }
    condition:
        $a at pe.entry_point

}