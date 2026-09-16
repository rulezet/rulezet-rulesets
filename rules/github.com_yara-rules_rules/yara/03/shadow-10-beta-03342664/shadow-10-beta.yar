import "pe"
rule Shadow_10_beta: PEiD
{
    strings:
        $a = { B9 00 00 BB 00 00 BE 03 01 BF 00 01 AD 33 C3 AB 86 DF F7 D3 E2 F6 68 00 01 C3 }
    condition:
        $a at pe.entry_point

}