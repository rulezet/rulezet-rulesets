import "pe"
rule RCryptor_V20_Private_Vaska: PEiD
{
    strings:
        $a = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF 59 BA ?? ?? ?? ?? F7 D1 83 F1 FF F7 D1 83 F1 FF 80 02 ?? F7 D1 83 F1 FF C0 0A ?? F7 D1 83 F1 FF 80 02 ?? F7 D1 83 F1 FF 80 32 ?? F7 D1 83 F1 FF 80 02 ?? F7 D1 83 F1 FF 42 49 85 C9 75 CD 1C 4F 8D 5B FD 62 1E 1C 4F 8D 5B FD 4D 9D B9 ?? ?? ?? ?? 1C 4F 8D 5B FD 22 1C 4F 8D 5B FD 8E A2 B9 B9 E2 83 DB E2 E5 4D CD 1E BF 60 AB 1F 4D DB 1E 1E 3D 1E 92 1B 8E DC 7D EC A4 E2 4D E5 20 C6 CC }
    condition:
        $a at pe.entry_point

}