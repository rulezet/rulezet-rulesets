import "pe"
rule Symantec_C_v210_v400_or_Zortech_C_v30r1_additional: PEiD
{
    strings:
        $a = { FA FC B8 ?? ?? 8E D8 }
    condition:
        $a at pe.entry_point

}