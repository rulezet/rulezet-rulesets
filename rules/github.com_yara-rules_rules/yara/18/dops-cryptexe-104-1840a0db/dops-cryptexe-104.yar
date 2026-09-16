import "pe"
rule DoPs_CryptExe_104: PEiD
{
    strings:
        $a = { 8B DC EB 01 EA BC 03 00 EB 01 EA 83 FC 03 74 05 EB 01 EA CD 20 EB 01 EA 8B E3 2E 89 26 13 00 EB 01 EA E8 C1 01 EA 2E 8B 26 13 00 1E 33 C0 8E D8 FA FF 06 06 00 2E F7 06 00 00 EB 00 FF 0E 06 00 FB 1F 2E 8C 1E 15 00 2E 8C 16 11 00 2E 89 26 13 }
    condition:
        $a at pe.entry_point

}