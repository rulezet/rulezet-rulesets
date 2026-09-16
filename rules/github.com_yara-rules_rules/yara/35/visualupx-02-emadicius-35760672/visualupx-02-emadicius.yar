import "pe"
rule VisualUPX_02_emadicius: PEiD
{
    strings:
        $a = { 66 C7 05 ?? ?? ?? 00 75 07 E9 ?? FE FF FF }
    condition:
        $a at pe.entry_point

}