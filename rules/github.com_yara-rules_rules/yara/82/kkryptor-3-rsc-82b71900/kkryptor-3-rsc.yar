import "pe"
rule kkryptor_3_rsc: PEiD
{
    strings:
        $a = { EB 66 87 DB 00 00 00 00 }
    condition:
        $a at pe.entry_point

}