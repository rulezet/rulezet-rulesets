import "pe"
rule FSG_v110_Eng_dulekxt_MASM32_additional: PEiD
{
    strings:
        $a = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }
    condition:
        $a at pe.entry_point

}