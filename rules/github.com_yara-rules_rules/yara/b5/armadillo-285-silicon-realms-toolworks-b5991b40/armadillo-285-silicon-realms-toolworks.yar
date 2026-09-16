import "pe"
rule Armadillo_285_Silicon_Realms_Toolworks: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 68 ?? ?? 00 68 00 ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 }
    condition:
        $a at pe.entry_point

}