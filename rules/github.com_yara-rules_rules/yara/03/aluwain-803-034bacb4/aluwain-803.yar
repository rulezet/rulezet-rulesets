import "pe"
rule Aluwain_803: PEiD
{
    strings:
        $a = { B8 00 00 50 E4 21 50 B8 00 00 8C DB 03 C3 50 B8 00 00 50 CB 50 }
    condition:
        $a at pe.entry_point

}