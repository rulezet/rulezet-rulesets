import "pe"
rule EEXE_Version_112_additional: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 03 73 ?? BA 1F 00 0E 1F B4 09 CD 21 B8 FF 4C CD 21 }
    condition:
        $a at pe.entry_point

}