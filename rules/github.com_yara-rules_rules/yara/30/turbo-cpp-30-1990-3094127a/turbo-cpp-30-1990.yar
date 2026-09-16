import "pe"
rule Turbo_Cpp_30_1990: PEiD
{
    strings:
        $a = { 8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B ?? ?? ?? 8E DA A3 ?? ?? 8C 06 }
    condition:
        $a at pe.entry_point

}