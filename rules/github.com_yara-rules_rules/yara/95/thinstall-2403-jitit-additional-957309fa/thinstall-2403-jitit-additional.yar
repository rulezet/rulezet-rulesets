import "pe"
rule Thinstall_2403_Jitit_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 48 D2 4B 00 E8 BC 87 F4 FF BB 04 0B 4D 00 33 C0 55 68 E8 D5 4B 00 64 FF 30 64 89 20 E8 9C F4 FF FF E8 F7 FB FF FF 6A 40 8D 55 F0 A1 F0 ED 4B 00 8B 00 E8 42 2E F7 FF 8B 4D F0 B2 01 A1 F4 C2 40 00 E8 F7 20 F5 FF }
    condition:
        $a at pe.entry_point

}