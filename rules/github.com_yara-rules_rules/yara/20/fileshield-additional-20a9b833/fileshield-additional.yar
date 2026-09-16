import "pe"
rule FileShield_additional: PEiD
{
    strings:
        $a = { 50 1E EB ?? 90 00 00 8B D8 }
    condition:
        $a at pe.entry_point

}