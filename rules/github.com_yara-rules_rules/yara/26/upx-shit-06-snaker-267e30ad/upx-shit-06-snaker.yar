import "pe"
rule UPX_Shit_06_snaker: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? B9 15 00 00 00 80 34 08 ?? E2 FA E9 }
    condition:
        $a at pe.entry_point

}