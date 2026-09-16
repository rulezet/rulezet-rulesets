import "pe"
rule Ding_Boys_PE_lock_007: PEiD
{
    strings:
        $a = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00 BE 3D 35 40 00 03 F5 B9 E4 02 00 00 E8 E4 02 00 00 71 99 00 00 83 3E 32 B8 77 40 00 74 38 67 BE C0 63 76 40 83 69 E1 82 1C C8 6B 76 40 BE 09 80 77 40 03 F6 A3 A9 6A 06 A4 77 40 66 }
    condition:
        $a at pe.entry_point

}