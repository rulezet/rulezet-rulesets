import "pe"
rule UPX_051_072_COM: PEiD
{
    strings:
        $a = { B9 00 00 BE 00 00 BF C0 FF FD F3 A4 FC F7 E1 93 87 F7 83 EE 00 19 ED 57 }
    condition:
        $a at pe.entry_point

}