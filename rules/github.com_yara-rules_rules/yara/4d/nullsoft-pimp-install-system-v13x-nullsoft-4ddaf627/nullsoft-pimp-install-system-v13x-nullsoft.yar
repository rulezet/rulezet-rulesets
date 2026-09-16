import "pe"
rule Nullsoft_PIMP_Install_System_v13x_Nullsoft: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }
    condition:
        $a at pe.entry_point

}