import "pe"
rule FSG_v110_Eng_dulekxt_: PEiD
{
    strings:
        $a = { EB ?? ?? ?? ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}