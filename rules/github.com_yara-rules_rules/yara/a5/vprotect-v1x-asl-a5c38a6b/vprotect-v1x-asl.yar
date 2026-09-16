import "pe"
rule VProtect_v1x_ASL: PEiD
{
    strings:
        $a = { 3B C0 74 1C EB 00 DB 2D ?? ?? ?? 00 FF FF FF FF FF FF FF FF 3D 40 FF 56 50 72 6F 74 65 63 74 00 ?? ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}