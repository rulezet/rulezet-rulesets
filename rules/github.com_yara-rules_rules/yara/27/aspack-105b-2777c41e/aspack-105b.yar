import "pe"
rule ASPack_105b: PEiD
{
    strings:
        $a = { 75 00 E9 }
    condition:
        $a at pe.entry_point

}