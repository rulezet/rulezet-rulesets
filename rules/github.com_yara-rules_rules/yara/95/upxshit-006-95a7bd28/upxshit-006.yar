import "pe"
rule UPXShit_006: PEiD
{
    strings:
        $a = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }
    condition:
        $a at pe.entry_point

}