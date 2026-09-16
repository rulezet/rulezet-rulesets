import "pe"
rule PCShrink_071_beta: PEiD
{
    strings:
        $a = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }
    condition:
        $a at pe.entry_point

}