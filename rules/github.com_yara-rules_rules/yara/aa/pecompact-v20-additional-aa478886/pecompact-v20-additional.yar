import "pe"
rule PECompact_v20_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D }
    condition:
        $a at pe.entry_point

}