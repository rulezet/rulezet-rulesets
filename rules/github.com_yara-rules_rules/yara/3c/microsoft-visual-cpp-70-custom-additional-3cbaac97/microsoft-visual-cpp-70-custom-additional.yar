import "pe"
rule Microsoft_Visual_Cpp_70_Custom_additional: PEiD
{
    strings:
        $a = { 60 BE 00 B0 44 00 8D BE 00 60 FB FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }
    condition:
        $a at pe.entry_point

}