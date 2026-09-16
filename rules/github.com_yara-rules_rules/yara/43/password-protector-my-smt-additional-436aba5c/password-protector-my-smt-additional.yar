import "pe"
rule Password_protector_my_SMT_additional: PEiD
{
    strings:
        $a = { C8 50 01 00 60 E8 EC 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 44 69 61 6C 6F 67 42 6F 78 49 6E 64 69 72 65 63 74 50 61 72 61 6D 41 00 53 65 6E 64 4D 65 73 73 61 67 65 41 00 45 6E 64 44 69 61 6C 6F }
    condition:
        $a at pe.entry_point

}