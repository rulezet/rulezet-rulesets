import "pe"
rule PeStubOEP_v1x_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? 00 FF E0 }
    condition:
        $a at pe.entry_point

}