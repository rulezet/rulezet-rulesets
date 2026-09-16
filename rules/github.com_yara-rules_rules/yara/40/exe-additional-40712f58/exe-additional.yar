import "pe"
rule EXE_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 E4 53 56 57 33 C0 89 45 E4 89 45 }
    condition:
        $a at pe.entry_point

}