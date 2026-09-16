import "pe"
rule MS_Visual_Cpp_v8_DLL_h_small_sig2: PEiD
{
    strings:
        $a = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01 }
    condition:
        $a at pe.entry_point

}