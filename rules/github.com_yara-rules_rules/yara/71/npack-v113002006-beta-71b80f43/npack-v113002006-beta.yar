import "pe"
rule nPack_v113002006_Beta: PEiD
{
    strings:
        $a = { 83 3D 4C ?? ?? 00 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 }
    condition:
        $a at pe.entry_point

}