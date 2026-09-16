import "pe"
rule Obsidium_unknown_version: PEiD
{
    strings:
        $a = { EB 01 ?? 50 EB 03 ?? ?? ?? E8 ?? 00 00 00 EB 03 }
    condition:
        $a at pe.entry_point

}