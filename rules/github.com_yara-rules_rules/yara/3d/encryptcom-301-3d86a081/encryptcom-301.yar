import "pe"
rule ENcryptCOM_301: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 02 77 02 CD 20 B0 4D 6A 64 5A EE }
    condition:
        $a at pe.entry_point

}