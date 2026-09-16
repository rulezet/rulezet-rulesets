import "pe"
rule LE_Exe_Executable_Image: PEiD
{
    strings:
        $a = { 4C 45 }
    condition:
        $a at pe.entry_point

}