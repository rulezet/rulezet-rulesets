import "pe"
rule WinZip_Self_Extractor_22_personal_edition_WinZip_Computing_h_additional: PEiD
{
    strings:
        $a = { 53 FF 15 58 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 5C 70 40 00 50 E8 15 FB FF FF 50 FF 15 8C 70 40 00 5B }
    condition:
        $a at pe.entry_point

}