import "pe"
rule BlackEnergy_DDoS_Bot_Crypter_additional: PEiD
{
    strings:
        $a = { 55 ?? ?? 81 EC 1C 01 00 00 53 56 57 6A 04 BE 00 30 00 00 56 FF 35 00 20 11 13 6A 00 E8 ?? 03 00 00 ?? ?? 83 C4 10 ?? FF 89 7D F4 0F }
    condition:
        $a at pe.entry_point

}