import "pe"
rule ASPAck_1061b: PEiD
{
    strings:
        $a = { 90 90 75 00 E9 }
    condition:
        $a at pe.entry_point

}