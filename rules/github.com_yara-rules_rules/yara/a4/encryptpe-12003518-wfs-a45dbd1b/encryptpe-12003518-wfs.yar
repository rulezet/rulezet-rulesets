import "pe"
rule EncryptPE_12003518_WFS: PEiD
{
    strings:
        $a = { 60 9C 64 FF 35 00 00 00 00 E8 79 }
    condition:
        $a at pe.entry_point

}