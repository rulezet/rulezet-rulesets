import "pe"
rule Obsidium_vxxxx_Obsidium_Software: PEiD
{
    strings:
        $a = { E8 47 19 }
    condition:
        $a at pe.entry_point

}