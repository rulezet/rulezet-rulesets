import "pe"
rule EXE_Cryptor_v240_v241_or_newer: PEiD
{
    strings:
        $a = { E8 3B FF FF FF 05 ?? ?? 00 00 FF E0 E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 }
    condition:
        $a at pe.entry_point

}