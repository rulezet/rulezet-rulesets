import "pe"
rule Nullsoft_Install_System_v20a7_Nullsoft: PEiD
{
    strings:
        $a = { 83 EC 0C 53 56 57 FF 15 BC 80 40 00 }
    condition:
        $a at pe.entry_point

}