import "pe"
rule FSG_v110_Eng_dulekxt_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? EB 02 }
    condition:
        $a at pe.entry_point

}