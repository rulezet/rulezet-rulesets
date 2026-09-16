import "pe"
rule RCryptor_v13_v14_Vaska_additional: PEiD
{
    strings:
        $a = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 }
    condition:
        $a at pe.entry_point

}