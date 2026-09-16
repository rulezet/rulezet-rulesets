import "pe"
rule CorelPhotoPaint_Image: PEiD
{
    strings:
        $a = { 43 50 54 37 46 49 4C 45 }
    condition:
        $a at pe.entry_point

}