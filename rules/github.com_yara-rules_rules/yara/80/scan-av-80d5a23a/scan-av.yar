import "pe"
rule SCAN_AV: PEiD
{
    strings:
        $a = { 1E 0E 1F B8 ?? ?? 8E C0 26 8A 1E ?? ?? 80 ?? ?? 72 }
    condition:
        $a at pe.entry_point

}