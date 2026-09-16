import "pe"
rule Obsidium_11114_11115_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 3F 1D 00 00 }
    condition:
        $a at pe.entry_point

}