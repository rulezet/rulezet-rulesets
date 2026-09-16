import "pe"
rule ProPack_214_m2_COM: PEiD
{
    strings:
        $a = { BE 4A 02 FC E8 3C 00 05 00 01 8B C8 E8 34 00 8B D0 03 C6 05 06 00 8B F8 83 C6 04 AD 32 E4 8B EE 8B F7 03 C1 8B F8 3B FE 76 0D FD 57 4E 4F 8B CA F3 A4 47 }
    condition:
        $a at pe.entry_point

}