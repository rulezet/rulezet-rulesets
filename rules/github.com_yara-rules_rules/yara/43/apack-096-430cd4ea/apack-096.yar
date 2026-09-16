import "pe"
rule aPack_096: PEiD
{
    strings:
        $a = { BE 0D 01 BF 00 70 8B CF FC 57 F3 A4 C3 BF 00 01 57 }
    condition:
        $a at pe.entry_point

}