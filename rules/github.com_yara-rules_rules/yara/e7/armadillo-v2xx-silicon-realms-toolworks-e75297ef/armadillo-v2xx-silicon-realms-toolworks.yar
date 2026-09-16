import "pe"
rule Armadillo_v2xx_Silicon_Realms_Toolworks: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 F0 67 4D 00 68 50 92 4B 00 64 A1 }
    condition:
        $a at pe.entry_point

}