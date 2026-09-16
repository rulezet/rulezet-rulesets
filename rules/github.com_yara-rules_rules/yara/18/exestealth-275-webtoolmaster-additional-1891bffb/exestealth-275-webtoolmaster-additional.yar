import "pe"
rule EXEStealth_275_WebtoolMaster_additional: PEiD
{
    strings:
        $a = { 33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21 }
    condition:
        $a at pe.entry_point

}