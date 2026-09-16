import "pe"
rule UltraPro_V10_SafeNet: PEiD
{
    strings:
        $a = { A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 }
    condition:
        $a at pe.entry_point

}