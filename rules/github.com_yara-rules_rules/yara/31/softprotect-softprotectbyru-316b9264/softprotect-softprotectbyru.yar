import "pe"
rule SoftProtect_SoftProtectbyru: PEiD
{
    strings:
        $a = { EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 59 83 01 01 80 39 5C }
        $b = { E8 0C 15 00 00 8D 85 2F 14 00 00 C7 00 00 00 00 00 E8 29 0F 00 00 E8 F6 14 00 00 8D 85 20 01 00 00 50 E8 AA 16 00 00 83 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}