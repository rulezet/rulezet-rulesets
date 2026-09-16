import "pe"
rule Alex_Protector_10_Alex_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 }
    condition:
        $a at pe.entry_point

}