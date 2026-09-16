import "pe"
rule FreeBASIC_v011_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 00 00 E8 01 00 00 00 C3 55 89 E5 }
    condition:
        $a at pe.entry_point

}