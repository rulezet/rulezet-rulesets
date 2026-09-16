import "pe"
rule Obsidium_v1111_additional: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}