import "pe"
rule Armadillo_v1xx_v2xx_Silicon_Realms_Toolworks: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 50 8C 4C 00 68 D0 82 4A 00 64 A1 }
    condition:
        $a at pe.entry_point

}