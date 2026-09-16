import "pe"
rule ExeLock_100: PEiD
{
    strings:
        $a = { 06 8C C8 8E C0 BE 17 00 26 8A 04 34 00 26 88 04 46 81 FE 0C 02 75 F1 }
    condition:
        $a at pe.entry_point

}