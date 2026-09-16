import "pe"
rule Turbo_C_1987_or_Borland_Cpp_1991: PEiD
{
    strings:
        $a = { FB BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 }
    condition:
        $a at pe.entry_point

}