import "pe"
rule PEiD_813_32Lite_v003a_Oleg_Prokhorov: PEiD
{
    strings:
        $a = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 00 10 ?? ?? 68 }
    condition:
        $a at pe.entry_point

}