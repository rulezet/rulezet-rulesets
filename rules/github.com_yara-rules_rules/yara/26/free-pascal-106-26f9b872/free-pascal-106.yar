import "pe"
rule Free_Pascal_106: PEiD
{
    strings:
        $a = { C6 05 ?? ?? 40 00 ?? E8 ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}