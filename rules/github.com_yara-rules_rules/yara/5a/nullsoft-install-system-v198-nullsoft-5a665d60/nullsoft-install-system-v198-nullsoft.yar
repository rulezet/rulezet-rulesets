import "pe"
rule Nullsoft_Install_System_v198_Nullsoft: PEiD
{
    strings:
        $a = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }
    condition:
        $a at pe.entry_point

}