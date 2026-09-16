import "pe"
rule PECompact_2xx_BitSum_Technologies: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }
    condition:
        $a at pe.entry_point

}