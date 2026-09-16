import "pe"
rule PE_Exe_Executable_Image: PEiD
{
    strings:
        $a = { 50 45 00 00 }
    condition:
        $a at pe.entry_point

}