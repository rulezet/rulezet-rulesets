import "pe"
rule tElock_v051: PEiD
{
    strings:
        $a = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }
    condition:
        $a at pe.entry_point

}