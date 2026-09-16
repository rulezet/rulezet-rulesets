import "pe"
rule kryptor_3_additional: PEiD
{
    strings:
        $a = { EB 66 87 DB }
    condition:
        $a at pe.entry_point

}