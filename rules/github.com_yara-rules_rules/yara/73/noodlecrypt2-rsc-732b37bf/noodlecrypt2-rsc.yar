import "pe"
rule Noodlecrypt2_rsc: PEiD
{
    strings:
        $a = { EB 01 9A E8 76 00 00 00 }
    condition:
        $a at pe.entry_point

}