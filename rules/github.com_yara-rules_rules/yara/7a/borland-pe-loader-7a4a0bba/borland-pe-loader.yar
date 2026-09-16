import "pe"
rule Borland_PE_loader: PEiD
{
    strings:
        $a = { 8C C8 8E D8 8C 1E 42 00 8C 06 3C 00 8C 06 46 00 8C 06 4A 00 8B DC 83 C3 0F D1 EB D1 EB D1 EB D1 EB 8C D0 03 D8 2B 1E 3C 00 B8 00 4A CD 21 B8 42 FB BB 33 32 CD 2F 83 FB 00 0F 84 00 01 BA 52 00 1E 07 BB 3E 00 B8 00 4B CD 21 0F 83 00 01 8E 06 }
    condition:
        $a at pe.entry_point

}