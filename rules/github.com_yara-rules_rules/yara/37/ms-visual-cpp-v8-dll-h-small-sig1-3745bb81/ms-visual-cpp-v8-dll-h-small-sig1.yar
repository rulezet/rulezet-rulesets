import "pe"
rule MS_Visual_Cpp_v8_DLL_h_small_sig1: PEiD
{
    strings:
        $a = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 ?? ?? ?? FF 5D E9 D6 FE FF FF CC CC CC CC CC }
    condition:
        $a at pe.entry_point

}