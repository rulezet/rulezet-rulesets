import "pe"
rule EncryptPE_V22006710_WFS_additional: PEiD
{
    strings:
        $a = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 }
    condition:
        $a at pe.entry_point

}