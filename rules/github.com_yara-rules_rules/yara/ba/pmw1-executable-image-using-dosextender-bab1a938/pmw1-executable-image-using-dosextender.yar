import "pe"
rule PMW1_Executable_Image_using_DOSExtender: PEiD
{
    strings:
        $a = { 50 4D 57 31 }
    condition:
        $a at pe.entry_point

}