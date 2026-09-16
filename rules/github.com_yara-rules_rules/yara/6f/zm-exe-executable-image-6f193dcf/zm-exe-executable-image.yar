import "pe"
rule ZM_Exe_Executable_Image: PEiD
{
    strings:
        $a = { 5A 4D }
    condition:
        $a at pe.entry_point

}