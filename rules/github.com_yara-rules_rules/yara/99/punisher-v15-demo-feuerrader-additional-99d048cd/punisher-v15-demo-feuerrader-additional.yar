import "pe"
rule PUNiSHER_V15_Demo_FEUERRADER_additional: PEiD
{
    strings:
        $a = { 3F 00 00 80 66 20 ?? 00 7E 20 ?? 00 92 20 ?? 00 A4 20 ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 }
    condition:
        $a at pe.entry_point

}