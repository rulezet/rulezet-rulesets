import "pe"
rule EP_v10_additional: PEiD
{
    strings:
        $a = { 81 EB 2A 01 8B 0F 1E 5B 03 CB 0E 51 B9 10 01 51 CB }
    condition:
        $a at pe.entry_point

}