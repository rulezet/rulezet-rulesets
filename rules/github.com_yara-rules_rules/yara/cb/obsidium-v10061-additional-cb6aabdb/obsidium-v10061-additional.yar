import "pe"
rule Obsidium_v10061_additional: PEiD
{
    strings:
        $a = { E8 AF 1C 00 00 }
    condition:
        $a at pe.entry_point

}