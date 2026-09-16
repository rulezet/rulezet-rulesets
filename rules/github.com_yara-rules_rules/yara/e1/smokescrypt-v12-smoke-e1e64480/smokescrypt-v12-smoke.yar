import "pe"
rule SmokesCrypt_v12_Smoke: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? 00 B8 ?? ?? ?? 00 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
    condition:
        $a at pe.entry_point

}