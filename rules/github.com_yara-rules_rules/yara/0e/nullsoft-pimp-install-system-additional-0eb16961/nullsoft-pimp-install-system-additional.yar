import "pe"
rule Nullsoft_PiMP_Install_System_additional: PEiD
{
    strings:
        $a = { 83 EC ?? 53 55 56 }
    condition:
        $a at pe.entry_point

}