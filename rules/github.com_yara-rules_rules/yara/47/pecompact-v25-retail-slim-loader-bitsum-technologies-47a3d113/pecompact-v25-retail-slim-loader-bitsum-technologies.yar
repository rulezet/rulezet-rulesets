import "pe"
rule PECompact_v25_Retail_Slim_Loader_Bitsum_Technologies: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }
    condition:
        $a at pe.entry_point

}