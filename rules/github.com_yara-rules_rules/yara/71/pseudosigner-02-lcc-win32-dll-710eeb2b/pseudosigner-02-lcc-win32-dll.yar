import "pe"
rule PseudoSigner_02_LCC_Win32_DLL: PEiD
{
    strings:
        $a = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }
    condition:
        $a at pe.entry_point

}