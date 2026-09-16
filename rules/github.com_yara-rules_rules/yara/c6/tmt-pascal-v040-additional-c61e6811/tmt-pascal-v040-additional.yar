import "pe"
rule TMT_Pascal_v040_additional: PEiD
{
    strings:
        $a = { 0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9 }
    condition:
        $a at pe.entry_point

}