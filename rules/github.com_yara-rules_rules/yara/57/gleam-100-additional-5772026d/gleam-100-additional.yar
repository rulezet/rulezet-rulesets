import "pe"
rule Gleam_100_additional: PEiD
{
    strings:
        $a = { 83 EC 0C 53 56 57 E8 24 02 00 }
    condition:
        $a at pe.entry_point

}