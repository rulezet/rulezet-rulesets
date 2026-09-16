import "pe"
rule Safeguard_103_Simonzh: PEiD
{
    strings:
        $a = { E8 ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}