import "pe"
rule PKTiny_162: PEiD
{
    strings:
        $a = { 1E 0E 1F B8 F0 FF 8E C0 26 8A 1E 0E 00 80 FB FD 72 0E B4 09 BA 58 01 CD 21 1F B8 00 4C CD 21 E9 FA 55 89 E5 8D 06 46 00 05 00 01 50 83 C4 02 31 DB C7 07 E9 DD C7 47 02 01 F4 C7 87 57 02 B9 08 8B 5E FE FF E3 EA FB 31 DB B8 0D 0E CD 10 B4 03 }
    condition:
        $a at pe.entry_point

}