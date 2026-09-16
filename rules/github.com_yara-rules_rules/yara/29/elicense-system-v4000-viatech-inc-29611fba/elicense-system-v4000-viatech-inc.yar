import "pe"
rule Elicense_System_V4000_ViaTech_Inc: PEiD
{
    strings:
        $a = { 00 00 00 00 63 79 62 00 65 6C 69 63 65 6E 34 30 2E 64 6C 6C 00 00 00 00 }
    condition:
        $a at pe.entry_point

}