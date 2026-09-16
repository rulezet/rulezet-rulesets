import "pe"
rule StarForce_30_StarForce_Technology_additional: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? FF 25 ?? ?? 57 }
    condition:
        $a at pe.entry_point

}