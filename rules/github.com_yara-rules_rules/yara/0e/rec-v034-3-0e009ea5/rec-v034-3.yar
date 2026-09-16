import "pe"
rule REC_v034_3: PEiD
{
    strings:
        $a = { 06 1E B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB }
    condition:
        $a at pe.entry_point

}