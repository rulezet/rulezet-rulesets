import "pe"
rule TAV: PEiD
{
    strings:
        $a = { E8 ?? ?? 4D 5A CB }
    condition:
        $a at pe.entry_point

}