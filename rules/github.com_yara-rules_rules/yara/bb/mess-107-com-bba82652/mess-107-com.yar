import "pe"
rule Mess_107_COM: PEiD
{
    strings:
        $a = { 46 55 43 4B 59 4F 55 1A FF 5F B9 FF FF F3 26 AC E3 02 EB 0C B8 00 70 50 9D 9C 58 25 00 70 75 18 BA 29 01 B4 09 CD 21 CD 20 33 38 36 2B 20 72 65 71 75 69 72 65 64 21 24 B4 30 CD 21 3C 02 77 02 CD 20 BD 47 01 FF E5 FA 66 33 C0 0F 23 F8 0F 23 }
    condition:
        $a at pe.entry_point

}