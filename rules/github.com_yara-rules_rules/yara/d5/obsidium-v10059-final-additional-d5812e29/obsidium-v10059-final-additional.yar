import "pe"
rule Obsidium_v10059_Final_additional: PEiD
{
    strings:
        $a = { E8 AB 1C }
    condition:
        $a at pe.entry_point

}