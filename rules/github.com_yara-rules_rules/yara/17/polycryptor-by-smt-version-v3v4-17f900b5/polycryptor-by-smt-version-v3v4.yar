import "pe"
rule PolyCryptor_by_SMT_Version_v3v4: PEiD
{
    strings:
        $a = { EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 ?? ?? ?? 20 62 79 20 53 4D 54 29 }
    condition:
        $a at pe.entry_point

}