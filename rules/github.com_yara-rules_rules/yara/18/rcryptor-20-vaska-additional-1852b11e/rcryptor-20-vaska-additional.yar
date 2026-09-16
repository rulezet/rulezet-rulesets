import "pe"
rule RCryptor_20_Vaska_additional: PEiD
{
    strings:
        $a = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF }
    condition:
        $a at pe.entry_point

}