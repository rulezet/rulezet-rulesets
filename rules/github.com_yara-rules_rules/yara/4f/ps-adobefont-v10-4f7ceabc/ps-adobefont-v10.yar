import "pe"
rule PS_AdobeFont_v10: PEiD
{
    strings:
        $a = { 80 01 ?? ?? 00 00 25 21 50 53 2D 41 64 6F 62 65 46 6F 6E 74 2D 31 2E 30 3A }
    condition:
        $a at pe.entry_point

}