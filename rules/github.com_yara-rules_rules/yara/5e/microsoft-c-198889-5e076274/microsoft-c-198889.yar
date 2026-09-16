import "pe"
rule Microsoft_C_198889: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 02 73 02 CD 20 BF 00 00 8B 36 02 00 2B F7 81 FE 00 10 72 03 BE 00 10 FA 8E D7 81 C4 00 00 FB 73 }
    condition:
        $a at pe.entry_point

}