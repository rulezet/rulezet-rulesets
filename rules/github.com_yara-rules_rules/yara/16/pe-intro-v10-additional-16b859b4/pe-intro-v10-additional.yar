import "pe"
rule PE_Intro_v10_additional: PEiD
{
    strings:
        $a = { 8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB }
    condition:
        $a at pe.entry_point

}