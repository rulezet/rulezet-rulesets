import "pe"
rule Powerbasic_210: PEiD
{
    strings:
        $a = { 2E 8C 1E 3E 00 2E C7 06 3C 00 00 00 E8 00 04 E8 00 00 E8 00 0A B8 FF FF 2E F7 06 4A 00 40 00 75 02 32 E4 50 E8 00 0B E8 10 00 58 E8 00 0B 2E 8E 1E 00 28 A1 02 00 B4 4C CD 21 E8 00 00 E8 00 01 72 00 E8 00 02 E8 00 02 E8 00 0E E8 00 16 }
    condition:
        $a at pe.entry_point

}