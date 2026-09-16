import "pe"
rule Obsidium_1250_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 }
    condition:
        $a at pe.entry_point

}