import "pe"
rule Winkript_v10_additional: PEiD
{
    strings:
        $a = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }
    condition:
        $a at pe.entry_point

}