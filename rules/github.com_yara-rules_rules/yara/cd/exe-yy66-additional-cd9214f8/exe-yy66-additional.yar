import "pe"
rule EXE_yy66_additional: PEiD
{
    strings:
        $a = { 68 78 18 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 }
    condition:
        $a at pe.entry_point

}