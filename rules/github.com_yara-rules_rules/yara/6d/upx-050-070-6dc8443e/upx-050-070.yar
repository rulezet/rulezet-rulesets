import "pe"
rule UPX_050_070: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D }
    condition:
        $a at pe.entry_point

}