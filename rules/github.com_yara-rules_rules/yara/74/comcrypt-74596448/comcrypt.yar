import "pe"
rule COMCRYPT: PEiD
{
    strings:
        $a = { B9 00 00 BE 00 01 89 F7 0E 1F 0E 07 BB 00 00 FC AD 31 D8 AB E2 FA C6 06 00 01 00 C6 06 01 01 00 C6 06 02 01 00 E9 00 00 }
    condition:
        $a at pe.entry_point

}