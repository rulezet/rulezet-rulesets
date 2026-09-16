import "pe"
rule StarForce_ProActive_11_StarForce_Technology: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? FF 25 ?? ?? 57 }
    condition:
        $a at pe.entry_point

}