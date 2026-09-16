import "pe"
rule RCryptor_v20_Hide_EP_Vaska_additional: PEiD
{
    strings:
        $a = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 DC 20 ?? 00 F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3 }
    condition:
        $a at pe.entry_point

}