import "pe"
rule LX_Exe_Executable_Image: PEiD
{
    strings:
        $a = { 4C 58 }
    condition:
        $a at pe.entry_point

}