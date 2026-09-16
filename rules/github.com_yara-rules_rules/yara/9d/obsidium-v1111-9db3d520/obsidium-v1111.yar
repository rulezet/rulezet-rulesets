import "pe"
rule Obsidium_v1111: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 E7 1C 00 00 }
    condition:
        $a at pe.entry_point

}