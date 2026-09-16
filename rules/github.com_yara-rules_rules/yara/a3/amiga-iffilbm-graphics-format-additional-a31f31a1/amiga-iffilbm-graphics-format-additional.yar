import "pe"
rule Amiga_IFFILBM_Graphics_format_additional: PEiD
{
    strings:
        $a = { 46 4F 52 4D ?? ?? ?? ?? 49 4C 42 4D 42 4D 48 44 }
    condition:
        $a at pe.entry_point

}