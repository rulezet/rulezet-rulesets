import "pe"
rule aPack_v062_additional: PEiD
{
    strings:
        $a = { 1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6 }
    condition:
        $a at pe.entry_point

}