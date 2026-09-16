import "pe"
rule Obsidium_V1304_Obsidium_Software_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}