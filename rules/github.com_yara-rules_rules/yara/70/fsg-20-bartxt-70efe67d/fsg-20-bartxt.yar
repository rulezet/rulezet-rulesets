import "pe"
rule FSG_20_bartxt: PEiD
{
    strings:
        $a = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 }
    condition:
        $a at pe.entry_point

}