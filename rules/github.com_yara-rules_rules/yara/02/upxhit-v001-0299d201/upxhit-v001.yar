import "pe"
rule UPXHiT_v001: PEiD
{
    strings:
        $a = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }
    condition:
        $a at pe.entry_point

}