import "pe"
rule PowerBASICCC_30x: PEiD
{
    strings:
        $a = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? ?? 00 04 00 0F 85 }
    condition:
        $a at pe.entry_point

}