import "pe"
rule kkryptor_5_rsc: PEiD
{
    strings:
        $a = { E8 03 00 00 00 E9 EB 6C 58 40 FF E0 }
    condition:
        $a at pe.entry_point

}