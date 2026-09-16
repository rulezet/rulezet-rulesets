import "pe"
rule PEBundle_20b5_31x_Jeremy_Collake: PEiD
{
    strings:
        $a = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 00 87 DD 01 AD ?? ?? ?? ?? 01 AD }
    condition:
        $a at pe.entry_point

}