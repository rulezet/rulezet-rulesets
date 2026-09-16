import "pe"
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Basic_MASM32_additional: PEiD
{
    strings:
        $a = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }
    condition:
        $a at pe.entry_point

}