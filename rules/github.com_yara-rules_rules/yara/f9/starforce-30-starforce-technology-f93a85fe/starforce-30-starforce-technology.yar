import "pe"
rule StarForce_30_StarForce_Technology: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? FF 25 ?? ?? 63 }
    condition:
        $a at pe.entry_point

}