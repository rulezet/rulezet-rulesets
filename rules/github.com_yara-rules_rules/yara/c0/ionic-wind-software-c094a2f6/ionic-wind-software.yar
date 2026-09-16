import "pe"
rule Ionic_Wind_Software: PEiD
{
    strings:
        $a = { 9B DB E3 9B DB E2 D9 2D 00 ?? ?? 00 55 89 E5 E8 }
    condition:
        $a at pe.entry_point

}