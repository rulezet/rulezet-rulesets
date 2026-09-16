import "pe"
rule PureBasic_DLL_Neil_Hodgson_additional: PEiD
{
    strings:
        $a = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }
    condition:
        $a at pe.entry_point

}