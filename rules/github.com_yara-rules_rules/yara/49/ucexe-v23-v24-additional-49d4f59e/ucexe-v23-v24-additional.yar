import "pe"
rule UCEXE_v23_v24_additional: PEiD
{
    strings:
        $a = { 50 1E 0E 1F FC 33 F6 E8 ?? ?? 16 07 33 F6 33 FF B9 ?? ?? F3 A5 06 B8 ?? ?? 50 CB }
    condition:
        $a at pe.entry_point

}