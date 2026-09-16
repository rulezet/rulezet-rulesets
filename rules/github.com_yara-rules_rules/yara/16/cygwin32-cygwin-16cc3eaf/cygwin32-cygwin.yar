import "pe"
rule Cygwin32_Cygwin: PEiD
{
    strings:
        $a = { 55 89 E5 83 EC 04 83 3D }
    condition:
        $a at pe.entry_point

}