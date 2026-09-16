import "pe"
rule Virus_Self_Destructor_200: PEiD
{
    strings:
        $a = { BE 00 00 B9 4C 00 FC 2E 81 34 EA C7 AD 2E 81 34 7E 20 AD E2 F2 81 EE 86 01 1E 06 8E 06 2C 00 33 FF 33 C0 26 3A 05 74 07 B9 FF FF F2 AE EB F4 83 C7 03 8B D7 06 1F 1E 52 B8 00 3D CD 21 72 17 8B D8 B4 3F B9 18 00 0E 1F 56 8B FE 81 C6 9C 01 8B }
    condition:
        $a at pe.entry_point

}