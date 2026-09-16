import "pe"
rule kkryptor_8_rsc: PEiD
{
    strings:
        $a = { EB 6A 87 DB 00 00 00 00 }
    condition:
        $a at pe.entry_point

}