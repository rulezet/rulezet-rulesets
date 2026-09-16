import "pe"
rule SVK_Protector_v111_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }
    condition:
        $a at pe.entry_point

}