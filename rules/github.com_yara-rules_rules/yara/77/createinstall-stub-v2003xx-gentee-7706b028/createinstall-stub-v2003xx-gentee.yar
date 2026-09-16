import "pe"
rule CreateInstall_Stub_v2003xx_Gentee: PEiD
{
    strings:
        $a = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 }
    condition:
        $a at pe.entry_point

}