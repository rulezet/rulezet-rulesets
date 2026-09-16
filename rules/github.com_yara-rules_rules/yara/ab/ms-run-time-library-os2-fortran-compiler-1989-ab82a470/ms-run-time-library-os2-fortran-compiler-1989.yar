import "pe"
rule MS_Run_Time_Library_OS2_FORTRAN_Compiler_1989: PEiD
{
    strings:
        $a = { B4 30 CD 21 86 E0 2E A3 ?? ?? 3D ?? ?? 73 }
    condition:
        $a at pe.entry_point

}