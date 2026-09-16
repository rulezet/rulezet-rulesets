import "pe"
rule W32Jeefo_PE_File_Infector_additional: PEiD
{
    strings:
        $a = { 55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 ?? ?? ?? FF D0 E8 ?? ?? ?? ?? C9 C3 }
    condition:
        $a at pe.entry_point

}