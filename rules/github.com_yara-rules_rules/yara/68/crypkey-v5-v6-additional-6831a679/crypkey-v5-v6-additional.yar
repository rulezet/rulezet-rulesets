import "pe"
rule CrypKey_v5_v6_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }
    condition:
        $a at pe.entry_point

}