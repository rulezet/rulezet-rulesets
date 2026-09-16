import "pe"
rule EXELOCK_666_104: PEiD
{
    strings:
        $a = { BA 20 08 BF E3 00 EB 01 EA E8 3F FF 7C 29 79 2F 1F F7 9C 75 F6 E6 A9 40 17 F9 A5 14 FB 9B 8E 1D EB 0D 55 BC E3 0D E1 F7 8D E6 55 AC FD 19 9B 0D E5 1D BE FC 1C 19 F1 E0 21 F6 1C 79 A3 C9 A7 DC BE DF 77 BB B4 71 A1 E3 AC D9 6E 7F AD AD 6A AE }
    condition:
        $a at pe.entry_point

}