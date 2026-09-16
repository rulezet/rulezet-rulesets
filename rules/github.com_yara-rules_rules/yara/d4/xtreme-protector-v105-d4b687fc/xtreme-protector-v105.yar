import "pe"
rule Xtreme_Protector_v105: PEiD
{
    strings:
        $a = { E9 ?? ?? 00 00 00 00 00 00 00 00 }
        $b = { B8 ?? ?? ?? 00 B9 75 ?? ?? 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}