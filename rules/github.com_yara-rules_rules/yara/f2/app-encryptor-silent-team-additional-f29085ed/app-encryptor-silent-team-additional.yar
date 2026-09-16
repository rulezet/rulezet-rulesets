import "pe"
rule App_Encryptor_Silent_Team_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC }
    condition:
        $a at pe.entry_point

}