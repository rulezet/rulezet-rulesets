import "pe"
rule ExeSplitter_10_Bill_Prisoner_TPOC: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? 00 4D 5A ?? 00 ?? 00 00 00 04 00 ?? 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}