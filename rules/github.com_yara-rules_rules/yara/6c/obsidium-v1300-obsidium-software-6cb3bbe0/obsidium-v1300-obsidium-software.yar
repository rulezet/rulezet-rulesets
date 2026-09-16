import "pe"
rule Obsidium_V1300_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 }
    condition:
        $a at pe.entry_point

}