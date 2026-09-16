import "pe"
rule TAV_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 4D 5A CB }
    condition:
        $a at pe.entry_point

}