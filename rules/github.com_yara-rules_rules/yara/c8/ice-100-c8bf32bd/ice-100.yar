import "pe"
rule Ice_100: PEiD
{
    strings:
        $a = { BE 26 01 8B FE 8B 0E 08 01 8B 16 02 01 B8 77 01 50 FC AD 33 C2 AB 8B D0 E2 F8 00 00 00 00 00 8D 0F 47 8C 77 F4 37 C6 FE 41 FC 0F 4D 0C BD 59 78 53 CD 7C 48 8D 0F 47 8C 7F F4 3F 85 AD 7F 55 83 85 08 FF F1 81 86 01 94 15 7B 2A 45 48 D1 DE EF }
    condition:
        $a at pe.entry_point

}