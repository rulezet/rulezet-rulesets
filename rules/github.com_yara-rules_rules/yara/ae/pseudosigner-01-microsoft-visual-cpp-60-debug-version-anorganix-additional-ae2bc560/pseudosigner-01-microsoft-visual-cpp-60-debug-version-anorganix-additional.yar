import "pe"
rule _PseudoSigner_01_Microsoft_Visual_Cpp_60_Debug_Version_Anorganix_additional: PEiD
{
    strings:
        $a = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 }
    condition:
        $a at pe.entry_point

}