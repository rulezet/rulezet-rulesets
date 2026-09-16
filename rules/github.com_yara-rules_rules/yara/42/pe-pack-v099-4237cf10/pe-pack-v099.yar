import "pe"
rule PE_Pack_v099: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2 }
    condition:
        $a at pe.entry_point

}