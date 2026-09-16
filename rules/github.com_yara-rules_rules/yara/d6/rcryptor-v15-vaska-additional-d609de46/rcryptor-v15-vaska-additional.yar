import "pe"
rule RCryptor_v15_Vaska_additional: PEiD
{
    strings:
        $a = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F }
    condition:
        $a at pe.entry_point

}