import "pe"
rule Microsoft_Visual_Basic_50_additional: PEiD
{
    strings:
        $a = { FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}