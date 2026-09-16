import "pe"
rule EXECryptor_v13045: PEiD
{
    strings:
        $a = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }
    condition:
        $a at pe.entry_point

}