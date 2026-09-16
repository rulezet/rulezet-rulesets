import "pe"
rule Trap_113_COM: PEiD
{
    strings:
        $a = { 8A F6 87 C9 B8 01 FA BA 45 59 87 C9 E8 00 00 8B FC 33 D2 36 8B 2D 87 DB 81 ED 0F 01 87 D2 44 44 8C D1 BA 99 CB 8E D2 33 D2 8E D1 8B CA 33 D2 B9 00 05 EB 02 CD 20 81 F9 E2 03 74 58 83 C1 FE 83 C2 01 EB EE 20 DC DC DC DC DC DC DC DC DC DC DC }
    condition:
        $a at pe.entry_point

}