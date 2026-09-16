import "pe"
rule InstallShield_3x_Custom_additional: PEiD
{
    strings:
        $a = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 00 A0 40 00 68 34 76 40 00 50 64 89 25 00 00 00 00 83 EC 60 53 56 57 89 65 E8 FF 15 8C E3 40 00 A3 70 B1 40 00 33 C0 A0 71 B1 40 00 A3 7C B1 40 00 A1 70 B1 }
    condition:
        $a at pe.entry_point

}