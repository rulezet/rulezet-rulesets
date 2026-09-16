import "pe"
rule PKLite_201: PEiD
{
    strings:
        $a = { 41 30 00 00 FF FF 00 00 FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F FF FF 00 00 FF FF }
    condition:
        $a at pe.entry_point

}