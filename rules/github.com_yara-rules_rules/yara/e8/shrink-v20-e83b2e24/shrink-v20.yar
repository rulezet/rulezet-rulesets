import "pe"
rule Shrink_v20: PEiD
{
    strings:
        $a = { E9 ?? ?? 50 9C FC BE ?? ?? 8B FE 8C C8 05 ?? ?? 8E C0 06 57 B9 }
    condition:
        $a at pe.entry_point

}