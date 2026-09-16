import "pe"
rule LC_300_1986: PEiD
{
    strings:
        $a = { FA B8 00 00 05 10 00 B1 04 D3 E8 8C CB 03 C3 8E D8 8E D0 }
    condition:
        $a at pe.entry_point

}