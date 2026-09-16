import "pe"
rule Microsoft_Visual_Studio_NET_additional: PEiD
{
    strings:
        $a = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}