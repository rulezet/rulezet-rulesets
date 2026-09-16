import "pe"
rule PEiD_3376_32Lite_v003a: PEiD
{
    strings:
        $a = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }
    condition:
        $a at pe.entry_point

}