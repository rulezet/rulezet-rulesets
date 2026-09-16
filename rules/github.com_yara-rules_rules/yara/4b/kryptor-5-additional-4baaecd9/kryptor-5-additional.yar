import "pe"
rule kryptor_5_additional: PEiD
{
    strings:
        $a = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }
    condition:
        $a at pe.entry_point

}