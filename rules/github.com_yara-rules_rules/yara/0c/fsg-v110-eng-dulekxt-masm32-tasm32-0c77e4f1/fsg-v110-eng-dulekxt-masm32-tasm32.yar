import "pe"
rule FSG_v110_Eng_dulekxt_MASM32_TASM32: PEiD
{
    strings:
        $a = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
    condition:
        $a at pe.entry_point

}