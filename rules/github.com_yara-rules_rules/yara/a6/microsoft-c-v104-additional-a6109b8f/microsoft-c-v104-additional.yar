import "pe"
rule Microsoft_C_v104_additional: PEiD
{
    strings:
        $a = { FA B8 ?? ?? 8E D8 8E D0 26 8B ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 04 D3 E3 EB }
    condition:
        $a at pe.entry_point

}