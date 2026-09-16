import "pe"
rule Pack_Master_v10_additional: PEiD
{
    strings:
        $a = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }
    condition:
        $a at pe.entry_point

}