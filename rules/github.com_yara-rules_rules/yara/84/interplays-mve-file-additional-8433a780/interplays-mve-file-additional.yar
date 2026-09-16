import "pe"
rule Interplays_MVE_file_additional: PEiD
{
    strings:
        $a = { 49 6E 74 65 72 70 6C 61 79 20 4D 56 45 20 46 69 6C 65 1A 00 1A }
    condition:
        $a at pe.entry_point

}