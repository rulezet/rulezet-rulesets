import "pe"
rule XPack_167_EXE: PEiD
{
    strings:
        $a = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB 01 9A 1E 0E 1F 8B EC EB 01 9A FA 33 DB 8E D3 BC 04 00 8F 06 EA 03 8F 06 EF 03 EB 01 9A 0E BE E2 03 56 5E 17 8B E5 83 C4 10 FB 1F 59 E8 C6 FF 33 DB 1E 8E DB C7 }
    condition:
        $a at pe.entry_point

}