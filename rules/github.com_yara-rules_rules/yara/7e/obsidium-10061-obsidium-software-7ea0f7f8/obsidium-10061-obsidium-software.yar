import "pe"
rule Obsidium_10061_Obsidium_Software: PEiD
{
    strings:
        $a = { E8 AF 1C 00 00 }
    condition:
        $a at pe.entry_point

}