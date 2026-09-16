import "pe"
rule Turbo_C_or_Borland_Cpp_additional: PEiD
{
    strings:
        $a = { BA ?? ?? 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA }
    condition:
        $a at pe.entry_point

}