import "pe"
rule Unpacked_BS_SFX_Archive_v19: PEiD
{
    strings:
        $a = { 1E 33 C0 50 B8 ?? ?? 8E D8 FA 8E D0 BC ?? ?? FB B8 ?? ?? CD 21 3C 03 73 }
    condition:
        $a at pe.entry_point

}