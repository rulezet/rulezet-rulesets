import "pe"
rule UPXHiT_001_sibaway7yahoocom: PEiD
{
    strings:
        $a = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}