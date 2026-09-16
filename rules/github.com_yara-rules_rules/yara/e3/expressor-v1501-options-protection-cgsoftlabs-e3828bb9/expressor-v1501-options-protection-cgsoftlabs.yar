import "pe"
rule eXPressor_v1501_Options_Protection_CGSoftLabs: PEiD
{
    strings:
        $a = { 5E 00 00 80 00 00 00 68 91 5D D4 27 35 C5 5A 4C A5 40 48 C4 08 4E C0 }
    condition:
        $a at pe.entry_point

}