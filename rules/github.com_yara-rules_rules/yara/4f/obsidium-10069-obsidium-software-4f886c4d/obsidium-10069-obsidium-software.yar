import "pe"
rule Obsidium_10069_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 A3 1C 00 00 }
    condition:
        $a at pe.entry_point

}