import "pe"
rule EncryptPE_22004810_22005314_WFS: PEiD
{
    strings:
        $a = { 60 9C 64 FF 35 00 00 00 00 E8 7A }
    condition:
        $a at pe.entry_point

}