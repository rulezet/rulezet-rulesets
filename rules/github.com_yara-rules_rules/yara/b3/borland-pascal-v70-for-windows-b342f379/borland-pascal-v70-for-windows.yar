import "pe"
rule Borland_Pascal_v70_for_Windows: PEiD
{
    strings:
        $a = { A1 C1 A3 83 75 57 51 33 C0 }
        $b = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}