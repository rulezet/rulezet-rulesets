import "pe"
rule WARNING_TROJAN_RobinPE: PEiD
{
    strings:
        $a = { 60 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 }
    condition:
        $a at pe.entry_point

}