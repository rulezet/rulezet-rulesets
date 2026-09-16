import "pe"
rule FixupPak_v120_additional: PEiD
{
    strings:
        $a = { 55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D }
    condition:
        $a at pe.entry_point

}