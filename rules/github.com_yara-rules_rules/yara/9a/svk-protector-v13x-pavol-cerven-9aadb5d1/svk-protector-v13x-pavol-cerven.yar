import "pe"
rule SVK_Protector_v13x_Pavol_Cerven: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? ?? 00 64 A0 23 }
    condition:
        $a at pe.entry_point

}