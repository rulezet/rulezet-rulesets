import "pe"
rule Packman_Executable_Image_Packer_0001_bubba_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF }
    condition:
        $a at pe.entry_point

}