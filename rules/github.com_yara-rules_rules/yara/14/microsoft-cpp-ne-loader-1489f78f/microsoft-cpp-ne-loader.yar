import "pe"
rule Microsoft_Cpp_NE_Loader: PEiD
{
    strings:
        $a = { 30 CD 21 86 E0 2E A3 00 00 3D 00 02 73 00 B8 00 00 8E D8 }
    condition:
        $a at pe.entry_point

}