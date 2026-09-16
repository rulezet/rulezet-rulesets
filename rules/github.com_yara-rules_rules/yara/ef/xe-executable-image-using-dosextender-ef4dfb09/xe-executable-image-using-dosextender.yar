import "pe"
rule XE_Executable_Image_using_DOSExtender: PEiD
{
    strings:
        $a = { 58 45 }
    condition:
        $a at pe.entry_point

}