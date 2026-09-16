import "pe"
rule RCryptor_V20_Private_Vaskanbsp_nbsp_SignByfly: PEiD
{
    strings:
        $a = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3 }
    condition:
        $a at pe.entry_point

}