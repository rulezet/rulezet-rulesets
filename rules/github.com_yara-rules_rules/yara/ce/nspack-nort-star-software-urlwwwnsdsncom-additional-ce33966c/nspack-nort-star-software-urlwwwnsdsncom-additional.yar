import "pe"
rule NSPack_Nort_Star_Software_urlwwwnsdsncom_additional: PEiD
{
    strings:
        $a = { 83 F9 00 74 28 43 8D B5 ?? ?? FF FF 8B 16 56 51 53 52 56 FF 33 FF 73 04 8B 43 08 03 C2 50 FF 95 ?? ?? FF FF 5A 5B 59 5E 83 C3 0C E2 E1 61 9D E9 ?? ?? ?? FF 8B B5 ?? ?? FF FF 0B F6 0F 84 97 00 00 00 8B 95 ?? ?? FF FF 03 F2 83 3E 00 75 0E 83 7E 04 00 75 08 }
    condition:
        $a at pe.entry_point

}