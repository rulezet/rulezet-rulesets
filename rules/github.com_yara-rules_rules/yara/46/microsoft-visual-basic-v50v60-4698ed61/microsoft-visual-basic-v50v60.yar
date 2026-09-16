import "pe"
rule Microsoft_Visual_Basic_v50v60: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 00 00 00 00 30 00 00 00 }
    condition:
        $a at pe.entry_point

}