import "pe"
rule from_NORMAN_Anti_Virus_Utilites_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 5B 52 45 2F 4E 44 44 53 5D 0D 0A }
    condition:
        $a at pe.entry_point

}