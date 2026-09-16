import "pe"
rule PE_Crypt32_v102_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5B 83 ?? ?? EB ?? 52 4E 44 21 }
    condition:
        $a at pe.entry_point

}