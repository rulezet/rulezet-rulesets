import "pe"
rule Excalibur_103_forgot: PEiD
{
    strings:
        $a = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 }
    condition:
        $a at pe.entry_point

}