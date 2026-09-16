import "pe"
rule Packman_0001_bubba_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 }
    condition:
        $a at pe.entry_point

}