import "pe"
rule Secure_21b: PEiD
{
    strings:
        $a = { 8C C8 05 00 00 50 B8 90 01 50 CB 00 }
    condition:
        $a at pe.entry_point

}