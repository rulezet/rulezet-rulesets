import "pe"
rule EP_ExE_Pack_V10_Elite_Coding_Group: PEiD
{
    strings:
        $a = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 }
    condition:
        $a at pe.entry_point

}