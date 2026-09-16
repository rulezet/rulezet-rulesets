import "pe"
rule Obsidium_1200_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 3F 1E 00 00 }
    condition:
        $a at pe.entry_point

}