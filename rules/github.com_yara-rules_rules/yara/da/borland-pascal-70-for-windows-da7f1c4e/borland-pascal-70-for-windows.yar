import "pe"
rule Borland_Pascal_70_for_Windows: PEiD
{
    strings:
        $a = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }
    condition:
        $a at pe.entry_point

}