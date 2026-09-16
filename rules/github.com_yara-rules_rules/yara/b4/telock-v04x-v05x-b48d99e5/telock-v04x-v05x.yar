import "pe"
rule tElock_v04x_v05x: PEiD
{
    strings:
        $a = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 ?? ?? 59 EB 01 }
    condition:
        $a at pe.entry_point

}