import "pe"
rule CPAV_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 4D 5A B1 01 93 01 00 00 02 }
    condition:
        $a at pe.entry_point

}