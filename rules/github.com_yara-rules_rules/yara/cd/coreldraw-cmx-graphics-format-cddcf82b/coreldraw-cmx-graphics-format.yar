import "pe"
rule CorelDraw_CMX_Graphics_format: PEiD
{
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 43 4D 58 31 }
    condition:
        $a at pe.entry_point

}