import "pe"
rule Gentee_Installer_Custom_additional: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC 14 04 00 00 53 56 57 6A 00 FF 15 08 41 40 00 68 00 50 40 00 FF 15 04 41 40 00 85 C0 74 29 6A 00 A1 00 20 40 00 ?? ?? ?? ?? 41 40 00 8B F0 6A 06 56 FF 15 1C 41 40 00 6A 03 56 FF }
    condition:
        $a at pe.entry_point

}