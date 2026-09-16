import "pe"
rule FSG_v133a_dulekxt: PEiD
{
    strings:
        $a = { BE A8 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }
    condition:
        $a at pe.entry_point

}