import "pe"
rule MoleBox_V23X_MoleStudiocom: PEiD
{
    strings:
        $a = { E8 00 00 00 00 60 E8 4F 00 00 00 }
    condition:
        $a at pe.entry_point

}