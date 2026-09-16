import "pe"
rule Inno_Setup_Module_v2018: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 }
    condition:
        $a at pe.entry_point

}