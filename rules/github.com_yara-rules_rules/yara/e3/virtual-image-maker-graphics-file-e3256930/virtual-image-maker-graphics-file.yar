import "pe"
rule Virtual_Image_Maker_Graphics_file: PEiD
{
    strings:
        $a = { 53 4F 4D 56 }
    condition:
        $a at pe.entry_point

}