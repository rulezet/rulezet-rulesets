import "pe"
rule MicroJoiner_v17_coban2k: PEiD
{
    strings:
        $a = { BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00 }
    condition:
        $a at pe.entry_point

}