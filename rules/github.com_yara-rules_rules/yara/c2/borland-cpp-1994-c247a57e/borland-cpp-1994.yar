import "pe"
rule Borland_Cpp_1994: PEiD
{
    strings:
        $a = { 8C CA 2E 89 ?? ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA A3 ?? ?? 8C }
    condition:
        $a at pe.entry_point

}