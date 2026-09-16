import "pe"
rule InstallShield_Stub_2003: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 C8 3B 42 00 68 ?? B8 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 C0 31 42 00 33 D2 8A D4 89 15 ?? EB 42 00 8B C8 81 E1 FF 00 00 00 89 0D ?? EB 42 00 C1 E1 08 03 CA 89 0D ?? EB 42 00 C1 E8 10 A3 ?? EB 42 00 6A 01 E8 C0 1C 00 00 59 85 C0 75 08 6A }
    condition:
        $a at pe.entry_point

}