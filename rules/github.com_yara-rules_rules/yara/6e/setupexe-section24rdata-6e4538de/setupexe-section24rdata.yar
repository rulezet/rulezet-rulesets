import "pe"
rule setupexe_Section24rdata: PEiD
{
    strings:
        $a = { 50 32 04 00 6A 32 04 00 00 00 00 00 EE 32 04 00 0C 33 04 00 2A 33 04 }
    condition:
        $a at pe.entry_point

}