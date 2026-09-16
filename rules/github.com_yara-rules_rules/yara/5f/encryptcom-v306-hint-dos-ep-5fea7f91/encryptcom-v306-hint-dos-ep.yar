import "pe"
rule ENcryptCOM_v306_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? B4 30 CD 21 3C 02 77 01 C3 }
    condition:
        $a at pe.entry_point

}