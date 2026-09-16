import "pe"
rule Jovian_VI_graphics_file: PEiD
{
    strings:
        $a = { 56 49 ?? ?? ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}