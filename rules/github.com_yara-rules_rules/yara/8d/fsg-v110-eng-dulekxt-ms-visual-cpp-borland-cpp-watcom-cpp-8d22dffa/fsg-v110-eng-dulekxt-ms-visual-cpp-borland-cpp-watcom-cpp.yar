import "pe"
rule FSG_v110_Eng_dulekxt_MS_Visual_Cpp_Borland_Cpp_Watcom_Cpp: PEiD
{
    strings:
        $a = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }
    condition:
        $a at pe.entry_point

}