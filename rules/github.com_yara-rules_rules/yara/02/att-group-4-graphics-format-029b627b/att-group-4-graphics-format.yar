import "pe"
rule ATT_Group_4_Graphics_format: PEiD
{
    strings:
        $a = { 01 00 ?? 00 3A 03 }
    condition:
        $a at pe.entry_point

}