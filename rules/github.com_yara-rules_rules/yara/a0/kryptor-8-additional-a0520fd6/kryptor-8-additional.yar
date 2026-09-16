import "pe"
rule kryptor_8_additional: PEiD
{
    strings:
        $a = { EB 6A 87 DB }
    condition:
        $a at pe.entry_point

}