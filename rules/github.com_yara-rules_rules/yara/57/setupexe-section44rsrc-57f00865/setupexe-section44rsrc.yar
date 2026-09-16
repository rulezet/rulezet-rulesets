import "pe"
rule setupexe_Section44rsrc: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 04 00 00 00 00 00 04 00 03 00 00 00 30 00 00 }
    condition:
        $a at pe.entry_point

}