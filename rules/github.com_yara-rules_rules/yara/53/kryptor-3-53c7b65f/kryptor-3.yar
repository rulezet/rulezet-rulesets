import "pe"
rule kryptor_3: PEiD
{
    strings:
        $a = { E8 03 E9 EB 6C 58 40 FF }
        $b = { EB 66 87 DB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}