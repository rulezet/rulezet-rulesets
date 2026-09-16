import "pe"
rule EXE_joiner_Amok_additional: PEiD
{
    strings:
        $a = { A1 14 A1 40 00 C1 E0 02 A3 18 A1 40 }
    condition:
        $a at pe.entry_point

}