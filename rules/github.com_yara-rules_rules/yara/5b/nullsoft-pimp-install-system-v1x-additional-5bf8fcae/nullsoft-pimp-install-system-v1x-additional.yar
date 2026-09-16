import "pe"
rule Nullsoft_PIMP_Install_System_v1x_additional: PEiD
{
    strings:
        $a = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}